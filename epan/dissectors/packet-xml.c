/* packet-xml.c
 * wireshark's xml dissector .
 *
 * (C) 2005, Luis E. Garcia Ontanon.
 *
 * $Id$
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <stdio.h>

#include <glib.h>
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/tvbparse.h>
#include <epan/dtd.h>
#include <epan/report_err.h>
#include <epan/filesystem.h>
#include <epan/prefs.h>

typedef struct _xml_ns_t {
    /* the name of this namespace */
	gchar* name;

    /* its fully qualified name */
	gchar* fqn;

	/* the contents of the whole element from <> to </> */
	int hf_tag;

	/* chunks of cdata from <> to </> excluding sub tags */
	int hf_cdata;

    /* the subtree for its sub items  */
	gint ett;

	GHashTable* attributes;
    /*  key:   the attribute name
        value: hf_id of what's between quotes */

    /* the namespace's namespaces */
    GHashTable* elements;
    /*  key:   the element name
        value: the child namespace */

	GPtrArray* element_names;
    /* imported directly from the parser and used while building the namespace */

} xml_ns_t;

typedef struct {
	proto_tree* tree;
	proto_item* item;
	proto_item* last_item;
	xml_ns_t* ns;
	int start_offset;
} xml_frame_t;

struct _attr_reg_data {
	GArray* hf;
	gchar* basename;
};


static gint ett_dtd = -1;
static gint ett_xmpli = -1;

static int hf_unknowwn_attrib = -1;
static int hf_comment = -1;
static int hf_xmlpi = -1;
static int hf_dtd_tag = -1;
static int hf_doctype = -1;

/* dissector handles */
static dissector_handle_t xml_handle;

/* parser definitions */
static tvbparse_wanted_t* want;
static tvbparse_wanted_t* want_ignore;
static tvbparse_wanted_t* want_heur;

static GHashTable* xmpli_names;
static GHashTable* media_types;

static xml_ns_t xml_ns = {"xml","/",-1,-1,-1,NULL,NULL,NULL};
static xml_ns_t unknown_ns = {"unknown","?",-1,-1,-1,NULL,NULL,NULL};
static xml_ns_t* root_ns;

static gboolean pref_heuristic = FALSE;

#define XML_CDATA -1000
#define XML_SCOPED_NAME -1001


GArray* hf_arr;
GArray* ett_arr;

static const gchar* default_media_types[] = {
	"text/xml",
	"text/vnd.wap.wml",
	"text/vnd.wap.si",
	"text/vnd.wap.sl",
	"text/vnd.wap.co",
	"text/vnd.wap.emn",
	"application/auth-policy+xml",
	"application/cpim-pidf+xml",
	"application/cpl+xml",
	"application/mathml+xml",
	"application/media_control+xml",
	"application/pidf+xml",
	"application/poc-settings+xml",
	"application/rdf+xml",
	"application/reginfo+xml",
	"application/resource-lists+xml",
	"application/rlmi+xml",
	"application/rls-services+xml",
	"application/smil",
	"application/simple-filter+xml",
	"application/soap+xml",
	"application/vnd.wv.csp+xml",
	"application/vnd.wv.csp.xml",
	"application/watcherinfo+xml",
	"application/xcap-att+xml",
	"application/xcap-caps+xml",
	"application/xcap-el+xml",
	"application/xcap-error+xml",
	"application/xml",
	"application/xml-dtd",
	"application/xpidf+xml",
	"application/xslt+xml",
	"image/svg+xml",
};

static void
dissect_xml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbparse_t* tt;
	tvbparse_elem_t* tok = NULL;
	static GPtrArray* stack = NULL;
	xml_frame_t* current_frame;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_append_str(pinfo->cinfo, COL_PROTOCOL, "/XML");

	if(!tree) return;

	if (stack != NULL)
		g_ptr_array_free(stack,TRUE);

	stack = g_ptr_array_new();
	current_frame = ep_alloc(sizeof(xml_frame_t));
	g_ptr_array_add(stack,current_frame);

	tt = tvbparse_init(tvb,0,-1,stack,want_ignore);
	current_frame->start_offset = 0;

	root_ns = NULL;

	if (pinfo->match_string)
		root_ns = g_hash_table_lookup(media_types,pinfo->match_string);

	if (! root_ns ) {
		root_ns = &xml_ns;
	}

	current_frame->ns = root_ns;

	current_frame->item = proto_tree_add_item(tree,current_frame->ns->hf_tag,tvb,0,-1,FALSE);
	current_frame->tree = proto_item_add_subtree(current_frame->item,current_frame->ns->ett);
	current_frame->last_item = current_frame->item;

	while(( tok = tvbparse_get(tt, want) )) ;
}

static gboolean dissect_xml_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    if ( pref_heuristic && tvbparse_peek(tvbparse_init(tvb,0,-1,NULL,want_ignore), want_heur)) {
        dissect_xml(tvb, pinfo, tree);
        return TRUE;
    } else {
        return FALSE;
    }
}

static void after_token(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok) {
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);
	int hfid;
	proto_item* pi;

	if (tok->id == XML_CDATA) {
		hfid = current_frame->ns ? current_frame->ns->hf_cdata : xml_ns.hf_cdata;
	} else if ( tok->id > 0) {
		hfid = tok->id;
	} else {
		hfid = xml_ns.hf_cdata;
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
	gchar* name = tvb_get_ephemeral_string(name_tok->tvb,name_tok->offset,name_tok->len);
	xml_ns_t* ns = g_hash_table_lookup(xmpli_names,name);

	int hf_tag;
	gint ett;

	g_strdown(name);
	if (!ns) {
		hf_tag = hf_xmlpi;
		ett = ett_xmpli;
	} else {
		hf_tag = ns->hf_tag;
		ett = ns->ett;
	}

	pi = proto_tree_add_item(current_frame->tree,hf_tag,tok->tvb,tok->offset,tok->len,FALSE);

	proto_item_set_text(pi, "%s", tvb_format_text(tok->tvb,tok->offset,(name_tok->offset - tok->offset) + name_tok->len));

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
    gchar* root_name;
	gchar* name;
	xml_ns_t* ns;
	xml_frame_t* new_frame;
	proto_item* pi;
	proto_tree* pt;

	if (name_tok->sub->id == XML_SCOPED_NAME) {
        tvbparse_elem_t* root_tok = name_tok->sub->sub;
        tvbparse_elem_t* leaf_tok = name_tok->sub->sub->next->next;
        xml_ns_t* nameroot_ns;

        root_name = tvb_get_ephemeral_string(root_tok->tvb,root_tok->offset,root_tok->len);
        name = tvb_get_ephemeral_string(leaf_tok->tvb,leaf_tok->offset,leaf_tok->len);

        nameroot_ns = g_hash_table_lookup(xml_ns.elements,root_name);

        if(nameroot_ns) {
            ns = g_hash_table_lookup(nameroot_ns->elements,name);
            if (!ns) {
                ns = &unknown_ns;
            }
        } else {
            ns = &unknown_ns;
        }

    } else {
        name = tvb_get_ephemeral_string(name_tok->tvb,name_tok->offset,name_tok->len);
        g_strdown(name);

        if(current_frame->ns) {
			ns = g_hash_table_lookup(current_frame->ns->elements,name);

			if (!ns) {
				if (! ( ns = g_hash_table_lookup(root_ns->elements,name) ) ) {
					ns = &unknown_ns;
				}
			}
		} else {
			ns = &unknown_ns;
		}
    }

    pi = proto_tree_add_item(current_frame->tree,ns->hf_tag,tok->tvb,tok->offset,tok->len,FALSE);
	proto_item_set_text(pi, "%s", tvb_format_text(tok->tvb,tok->offset,(name_tok->offset - tok->offset) + name_tok->len));

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

static void after_untag(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok){
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
	gchar* name = tvb_get_ephemeral_string(tok->sub->tvb,tok->sub->offset,tok->sub->len);
	tvbparse_elem_t* value = tok->sub->next->next->data;
	int* hfidp;
	int hfid;

	g_strdown(name);
	if(current_frame->ns && (hfidp = g_hash_table_lookup(current_frame->ns->attributes,name) )) {
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



static void init_xml_parser(void) {
	tvbparse_wanted_t* want_name = tvbparse_chars(-1,1,0,"abcdefghijklmnopqrstuvwxyz-_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",NULL,NULL,NULL);
	tvbparse_wanted_t* want_attr_name = tvbparse_chars(-1,1,0,"abcdefghijklmnopqrstuvwxyz-_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:",NULL,NULL,NULL);

    tvbparse_wanted_t* want_scoped_name = tvbparse_set_seq(XML_SCOPED_NAME, NULL, NULL, NULL,
                                                           want_name,
                                                           tvbparse_char(-1,":",NULL,NULL,NULL),
                                                           want_name,
                                                           NULL);

    tvbparse_wanted_t* want_tag_name = tvbparse_set_oneof(0, NULL, NULL, NULL,
                                                          want_scoped_name,
                                                          want_name,
                                                          NULL);

    tvbparse_wanted_t* want_attrib_value = tvbparse_set_oneof(0, NULL, NULL, get_attrib_value,
                                                              tvbparse_quoted(-1, NULL, NULL, tvbparse_shrink_token_cb,'\"','\\'),
                                                              tvbparse_quoted(-1, NULL, NULL, tvbparse_shrink_token_cb,'\'','\\'),
                                                              tvbparse_chars(-1,1,0,"0123456789",NULL,NULL,NULL),
                                                              want_name,
                                                              NULL);

	tvbparse_wanted_t* want_attributes = tvbparse_one_or_more(-1, NULL, NULL, NULL,
															  tvbparse_set_seq(-1, NULL, NULL, after_attrib,
                                                                               want_attr_name,
																			   tvbparse_char(-1,"=",NULL,NULL,NULL),
																			   want_attrib_value,
																			   NULL));

	tvbparse_wanted_t* want_stoptag = tvbparse_set_oneof(-1,NULL,NULL,NULL,
														 tvbparse_char(-1, ">", NULL, NULL, after_open_tag),
														 tvbparse_string(-1, "/>", NULL, NULL, after_closed_tag),
														 NULL);

	tvbparse_wanted_t* want_stopxmlpi = tvbparse_string(-1,"?>",NULL,NULL,after_xmlpi);

    tvbparse_wanted_t* want_comment = tvbparse_set_seq(hf_comment,NULL,NULL,after_token,
                                                       tvbparse_string(-1,"<!--",NULL,NULL,NULL),
                                                       tvbparse_until(-1,NULL,NULL,NULL,
                                                                      tvbparse_string(-1,"-->",NULL,NULL,NULL),
                                                                      TP_UNTIL_INCLUDE),
                                                       NULL);

    tvbparse_wanted_t* want_xmlpi = tvbparse_set_seq(hf_xmlpi,NULL,before_xmpli,NULL,
                                                     tvbparse_string(-1,"<?",NULL,NULL,NULL),
                                                     want_name,
                                                     tvbparse_set_oneof(-1,NULL,NULL,NULL,
                                                                        want_stopxmlpi,
                                                                        tvbparse_set_seq(-1,NULL,NULL,NULL,
                                                                                         want_attributes,
                                                                                         want_stopxmlpi,
                                                                                         NULL),
                                                                        NULL),
                                                     NULL);

    tvbparse_wanted_t* want_closing_tag = tvbparse_set_seq(0,NULL,NULL,after_untag,
                                                           tvbparse_char(-1, "<", NULL, NULL, NULL),
                                                           tvbparse_char(-1, "/", NULL, NULL, NULL),
                                                           want_tag_name,
                                                           tvbparse_char(-1, ">", NULL, NULL, NULL),
                                                           NULL);

    tvbparse_wanted_t* want_doctype_start = tvbparse_set_seq(-1,NULL,before_dtd_doctype,NULL,
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
                                                                                                                TP_UNTIL_INCLUDE),
                                                                                                 NULL),
                                                                                NULL),
                                                             NULL);

    tvbparse_wanted_t* want_dtd_tag = tvbparse_set_seq(hf_dtd_tag,NULL,NULL,after_token,
                                                       tvbparse_char(-1,"<",NULL,NULL,NULL),
                                                       tvbparse_char(-1,"!",NULL,NULL,NULL),
                                                       tvbparse_until(-1,NULL,NULL,NULL,
                                                                      tvbparse_char(-1, ">", NULL, NULL, NULL),
                                                                      TP_UNTIL_INCLUDE),
                                                       NULL);

    tvbparse_wanted_t* want_tag = tvbparse_set_seq(-1, NULL, before_tag, NULL,
                                                   tvbparse_char(-1,"<",NULL,NULL,NULL),
                                                   want_tag_name,
                                                   tvbparse_set_oneof(-1,NULL,NULL,NULL,
                                                                      tvbparse_set_seq(-1,NULL,NULL,NULL,
                                                                                       want_attributes,
                                                                                       want_stoptag,
                                                                                       NULL),
                                                                      want_stoptag,
                                                                      NULL),
                                                   NULL);

    tvbparse_wanted_t* want_dtd_close = tvbparse_set_seq(-1,NULL,NULL,after_dtd_close,
                                                         tvbparse_char(-1,"]",NULL,NULL,NULL),
                                                         tvbparse_char(-1,">",NULL,NULL,NULL),
                                                         NULL);

    want_ignore = tvbparse_chars(-1,1,0," \t\r\n",NULL,NULL,NULL);


	want = tvbparse_set_oneof(-1, NULL, NULL, NULL,
							  want_comment,
							  want_xmlpi,
							  want_closing_tag,
							  want_doctype_start,
							  want_dtd_close,
							  want_dtd_tag,
							  want_tag,
							  tvbparse_not_chars(XML_CDATA,1,0,"<",NULL,NULL,after_token),
							  tvbparse_not_chars(-1,1,0," \t\r\n",NULL,NULL,unrecognized_token),
							  NULL);

    want_heur = tvbparse_set_oneof(-1, NULL, NULL, NULL,
                                   want_comment,
                                   want_xmlpi,
                                   want_doctype_start,
                                   want_dtd_tag,
                                   want_tag,
                                   NULL);

}


static xml_ns_t* xml_new_namespace(GHashTable* hash, gchar* name, ...) {
	xml_ns_t* ns = g_malloc(sizeof(xml_ns_t));
	va_list ap;
	gchar* attr_name;

	ns->name = g_strdup(name);
	ns->hf_tag = -1;
	ns->hf_cdata = -1;
	ns->ett = -1;
	ns->attributes = g_hash_table_new(g_str_hash,g_str_equal);
	ns->elements = g_hash_table_new(g_str_hash,g_str_equal);

	va_start(ap,name);

	while(( attr_name = va_arg(ap,gchar*) )) {
		int* hfp = g_malloc(sizeof(int));
		*hfp = -1;
		g_hash_table_insert(ns->attributes,g_strdup(attr_name),hfp);
	};

	va_end(ap);

	g_hash_table_insert(hash,ns->name,ns);

	return ns;
}


static void add_xml_field(GArray* hfs, int* p_id, gchar* name, gchar* fqn) {
	hf_register_info hfri;

	hfri.p_id = p_id;
	hfri.hfinfo.name = name;
	hfri.hfinfo.abbrev = fqn;
	hfri.hfinfo.type = FT_STRING;
	hfri.hfinfo.display = BASE_NONE;
	hfri.hfinfo.strings = NULL;
	hfri.hfinfo.bitmask = 0x0;
	hfri.hfinfo.blurb = "";
	hfri.hfinfo.id = 0;
	hfri.hfinfo.parent = 0;
	hfri.hfinfo.ref_count = 0;
	hfri.hfinfo.bitshift = 0;
	hfri.hfinfo.same_name_next = NULL;
	hfri.hfinfo.same_name_prev = NULL;

	g_array_append_val(hfs,hfri);
}

static void add_xml_attribute_names(gpointer k, gpointer v, gpointer p) {
	struct _attr_reg_data* d = p;
	gchar* basename = g_strdup_printf("%s.%s",d->basename,(gchar*)k);
	add_xml_field(d->hf, (int*) v, (gchar*)k, basename);
}


static void add_xmlpi_namespace(gpointer k _U_, gpointer v, gpointer p) {
	xml_ns_t* ns = v;
	gchar* basename = g_strdup_printf("%s.%s",(gchar*)p,ns->name);
	gint* ett_p = &(ns->ett);
	struct _attr_reg_data d;

	add_xml_field(hf_arr, &(ns->hf_tag), basename, basename);

	g_array_append_val(ett_arr,ett_p);

	d.basename = basename;
	d.hf = hf_arr;

	g_hash_table_foreach(ns->attributes,add_xml_attribute_names,&d);

}

static void destroy_dtd_data(dtd_build_data_t* dtd_data) {

	if(dtd_data->proto_name) g_free(dtd_data->proto_name);
	if(dtd_data->media_type) g_free(dtd_data->media_type);
	if(dtd_data->description) g_free(dtd_data->description);
	if(dtd_data->proto_root) g_free(dtd_data->proto_root);

    g_string_free(dtd_data->error,TRUE);


	while(dtd_data->elements->len) {
		dtd_named_list_t* nl = g_ptr_array_remove_index_fast(dtd_data->elements,0);
		g_ptr_array_free(nl->list,TRUE);
		g_free(nl);
	}

	g_ptr_array_free(dtd_data->elements,TRUE);

	while(dtd_data->attributes->len) {
		dtd_named_list_t* nl = g_ptr_array_remove_index_fast(dtd_data->attributes,0);
		g_ptr_array_free(nl->list,TRUE);
		g_free(nl);
	}

	g_ptr_array_free(dtd_data->attributes,TRUE);

	g_free(dtd_data);

}


static void copy_attrib_item(gpointer k, gpointer v _U_, gpointer p) {
	gchar* key = g_strdup(k);
	int* value = g_malloc(sizeof(int));
	GHashTable* dst = p;

	*value = -1;
	g_hash_table_insert(dst,key,value);

}

static GHashTable* copy_attributes_hash(GHashTable* src) {
	GHashTable* dst = g_hash_table_new(g_str_hash,g_str_equal);

	g_hash_table_foreach(src,copy_attrib_item,dst);

	return dst;
}

static xml_ns_t* duplicate_element(xml_ns_t* orig) {
	xml_ns_t* new_item  = g_malloc(sizeof(xml_ns_t));
	guint i;

	new_item->name = g_strdup(orig->name);
	new_item->hf_tag = -1;
	new_item->hf_cdata = -1;
	new_item->ett = -1;
	new_item->attributes = copy_attributes_hash(orig->attributes);
	new_item->elements =  g_hash_table_new(g_str_hash,g_str_equal);
	new_item->element_names = g_ptr_array_new();

	for(i=0; i < orig->element_names->len; i++) {
		g_ptr_array_add(new_item->element_names,
						   g_ptr_array_index(orig->element_names,i));
	}

	return new_item;
}

static gchar* fully_qualified_name(GPtrArray* hier, gchar* name) {
	guint i;
	GString* s = g_string_new("");
	gchar* str;

	for (i = 0; i < hier->len; i++) {
		g_string_sprintfa(s, "%s.",(gchar*)g_ptr_array_index(hier,i));
	}

	g_string_append(s,name);
	str = s->str;
	g_string_free(s,FALSE);

	return str;
}


static xml_ns_t* make_xml_hier(gchar* elem_name,
								  xml_ns_t* root,
								  GHashTable* elements,
								  GPtrArray* hier,
								  GString* error,
								  GArray* hfs,
								  GArray* etts) {
	xml_ns_t* new;
	xml_ns_t* orig;
	gchar* fqn;
	gint* ett_p;
	struct _attr_reg_data d;
    gboolean recurred = FALSE;
    guint i;

    if ( g_str_equal(elem_name,root->name) ) {
        return NULL;
    }

	if (! ( orig = g_hash_table_lookup(elements,elem_name) )) {
		g_string_sprintfa(error,"element '%s' is not defined\n", elem_name);
		return NULL;
	}

    for (i = 0; i < hier->len; i++) {
        if( strcmp(elem_name,(gchar*) g_ptr_array_index(hier,i) ) == 0 ) {
            recurred = TRUE;
        }
    }

    if (recurred) {
        return NULL;
    }

	fqn = fully_qualified_name(hier,elem_name);

	new = duplicate_element(orig);
	new->fqn = fqn;

    add_xml_field(hfs, &(new->hf_tag), g_strdup(elem_name), fqn);
	add_xml_field(hfs, &(new->hf_cdata), g_strdup(elem_name), fqn);

	ett_p = &new->ett;
	g_array_append_val(etts,ett_p);

	d.basename = fqn;
	d.hf = hfs;

	g_hash_table_foreach(new->attributes,add_xml_attribute_names,&d);

	while(new->element_names->len) {
		gchar* child_name = g_ptr_array_remove_index(new->element_names,0);
		xml_ns_t* child_element = NULL;

        g_ptr_array_add(hier,elem_name);
        child_element = make_xml_hier(child_name, root, elements, hier,error,hfs,etts);
        g_ptr_array_remove_index_fast(hier,hier->len - 1);

		if (child_element) {
			g_hash_table_insert(new->elements,child_element->name,child_element);
		}
    }

	g_ptr_array_free(new->element_names,TRUE);
	new->element_names = NULL;
	return new;
}

static gboolean free_both(gpointer k, gpointer v, gpointer p _U_) {
    g_free(k);
    g_free(v);
    return TRUE;
}

static gboolean free_elements(gpointer k _U_, gpointer v, gpointer p _U_) {
    xml_ns_t* e = v;
    g_free(e->name);
    g_hash_table_foreach_remove(e->attributes,free_both,NULL);
    g_hash_table_destroy(e->attributes);
    g_hash_table_destroy(e->elements);

    while (e->element_names->len) {
        g_free(g_ptr_array_remove_index(e->element_names,0));
    }

    g_ptr_array_free(e->element_names,TRUE);
    g_free(e);

    return TRUE;
}

static void register_dtd(dtd_build_data_t* dtd_data, GString* errors) {
	GHashTable* elements = g_hash_table_new(g_str_hash,g_str_equal);
	gchar* root_name = NULL;
	xml_ns_t* root_element = NULL;
	GArray* hfs;
	GArray* etts;
	GPtrArray* hier;
	gchar* curr_name;
    GPtrArray* element_names = g_ptr_array_new();

    /* we first populate elements with the those coming from the parser */
	while(dtd_data->elements->len) {
		dtd_named_list_t* nl = g_ptr_array_remove_index(dtd_data->elements,0);
		xml_ns_t* element = g_malloc(sizeof(xml_ns_t));

		/* we will use the first element found as root in case no other one was given. */
		if (root_name == NULL)
            root_name = g_strdup(nl->name);

		element->name = nl->name;
		element->element_names = nl->list;
		element->hf_tag = -1;
		element->hf_cdata = -1;
		element->ett = -1;
		element->attributes = g_hash_table_new(g_str_hash,g_str_equal);
		element->elements = g_hash_table_new(g_str_hash,g_str_equal);

        if( g_hash_table_lookup(elements,element->name) ) {
            g_string_sprintfa(errors,"element %s defined more than once\n", element->name);
            free_elements(NULL,element,NULL);
        } else {
            g_hash_table_insert(elements,element->name,element);
            g_ptr_array_add(element_names,g_strdup(element->name));
		}

		g_free(nl);
	}

	/* then we add the attributes to its relative elements */
	while(dtd_data->attributes->len) {
		dtd_named_list_t* nl = g_ptr_array_remove_index(dtd_data->attributes,0);
		xml_ns_t* element = g_hash_table_lookup(elements,nl->name);

		if (!element) {
			g_string_sprintfa(errors,"element %s is not defined\n", nl->name);

            goto next_attribute;
		}

		while(nl->list->len) {
			gchar* name = g_ptr_array_remove_index(nl->list,0);
			int* id_p = g_malloc(sizeof(int));

			*id_p = -1;
			g_hash_table_insert(element->attributes,name,id_p);
		}

next_attribute:
		g_free(nl->name);
		g_ptr_array_free(nl->list,TRUE);
		g_free(nl);
	}

    /* if a proto_root is defined in the dtd we'll use that as root */
	if( dtd_data->proto_root ) {
        if(root_name)
            g_free(root_name);
        root_name = g_strdup(dtd_data->proto_root);
	}

    /* we use a stack with the names to avoid recurring infinitelly */
	hier = g_ptr_array_new();

    /*
     * if a proto name was given in the dtd the dtd will be used as a protocol
     * or else the dtd will be loaded as a branch of the xml namespace
     */
	if( ! dtd_data->proto_name ) {
		hfs = hf_arr;
		etts = ett_arr;
		g_ptr_array_add(hier,g_strdup("xml"));
		root_element = &xml_ns;
	} else {
        /*
         * if we were given a proto_name the namespace will be registered
         * as an indipendent protocol with its own hf and ett arrays.
         */
	    hfs = g_array_new(FALSE,FALSE,sizeof(hf_register_info));
	    etts = g_array_new(FALSE,FALSE,sizeof(gint*));
	}

    /* the root element of the dtd's namespace */
	root_element = g_malloc(sizeof(xml_ns_t));
    root_element->name = g_strdup(root_name);
    root_element->fqn = root_element->name;
    root_element->hf_tag = -1;
    root_element->hf_cdata = -1;
    root_element->ett = -1;
    root_element->elements = g_hash_table_new(g_str_hash,g_str_equal);
    root_element->element_names = element_names;

    /*
     * we can either create a namespace as a flat namespace
     * in which all the elements are at the root level
     * or we can create a recursive namespace
     */
    if (dtd_data->recursion) {
        xml_ns_t* orig_root;

        make_xml_hier(root_name, root_element, elements,hier,errors,hfs,etts);

        g_hash_table_insert(root_element->elements,root_element->name,root_element);

        orig_root = g_hash_table_lookup(elements,root_name);

        /* if the root element was defined copy its attrlist to the child */
        if(orig_root) {
            struct _attr_reg_data d;

            d.basename = root_name;
            d.hf = hfs;

            root_element->attributes = copy_attributes_hash(orig_root->attributes);
            g_hash_table_foreach(root_element->attributes,add_xml_attribute_names,&d);
        } else {
            root_element->attributes = g_hash_table_new(g_str_hash,g_str_equal);
        }

        /* we then create all the sub hierachies to catch the recurred cases */
        g_ptr_array_add(hier,root_name);

        while(root_element->element_names->len) {
            curr_name = g_ptr_array_remove_index(root_element->element_names,0);

            if( ! g_hash_table_lookup(root_element->elements,curr_name) ) {
                xml_ns_t* new = make_xml_hier(curr_name, root_element, elements,hier,errors,hfs,etts);
                g_hash_table_insert(root_element->elements,new->name,new);
            }

            g_free(curr_name);
        }

    } else {
        /* a flat namespace */
        g_ptr_array_add(hier,root_name);

        root_element->attributes = g_hash_table_new(g_str_hash,g_str_equal);

        while(root_element->element_names->len) {
            xml_ns_t* new;
            gint* ett_p;
            struct _attr_reg_data d;

            curr_name = g_ptr_array_remove_index(root_element->element_names,0);
            new = duplicate_element(g_hash_table_lookup(elements,curr_name));
            new->fqn = fully_qualified_name(hier, curr_name);

            add_xml_field(hfs, &(new->hf_tag), curr_name, new->fqn);
            add_xml_field(hfs, &(new->hf_cdata), curr_name, new->fqn);

            d.basename = new->fqn;
            d.hf = hfs;

            g_hash_table_foreach(new->attributes,add_xml_attribute_names,&d);

            ett_p = &new->ett;
            g_array_append_val(etts,ett_p);

            g_ptr_array_free(new->element_names,TRUE);

            g_hash_table_insert(root_element->elements,new->name,new);
        }
    }

    g_ptr_array_free(element_names,TRUE);

	g_ptr_array_free(hier,TRUE);

    /*
     * if we were given a proto_name the namespace will be registered
     * as an indipendent protocol.
     */
	if( dtd_data->proto_name ) {
        gint* ett_p;

		if ( ! dtd_data->description) {
			dtd_data->description = g_strdup(root_name);
		}

        ett_p = &root_element->ett;
        g_array_append_val(etts,ett_p);

        add_xml_field(hfs, &root_element->hf_cdata, root_element->name, root_element->fqn);

		root_element->hf_tag = proto_register_protocol(dtd_data->description, dtd_data->proto_name, root_element->name);
		proto_register_field_array(root_element->hf_tag, (hf_register_info*)hfs->data, hfs->len);
		proto_register_subtree_array((gint**)etts->data, etts->len);

		if (dtd_data->media_type) {
			g_hash_table_insert(media_types,dtd_data->media_type,root_element);
			dtd_data->media_type = NULL;
		}

		dtd_data->description = NULL;
		dtd_data->proto_name = NULL;
		g_array_free(hfs,FALSE);
		g_array_free(etts,TRUE);
	}

    g_hash_table_insert(xml_ns.elements,root_element->name,root_element);

    g_hash_table_foreach_remove(elements,free_elements,NULL);
    g_hash_table_destroy(elements);

	destroy_dtd_data(dtd_data);

    if (root_name)
        g_free(root_name);
}

#if GLIB_MAJOR_VERSION < 2
#  define DIRECTORY_T DIR
#  define FILE_T struct dirent
#  define OPENDIR_OP(name) opendir(name)
#  define DIRGETNEXT_OP(dir) readdir(dir)
#  define GETFNAME_OP(file) (gchar *)file->d_name
#  define CLOSEDIR_OP(dir) closedir(dir)
#else /* GLIB 2 */
#  define DIRECTORY_T GDir
#  define FILE_T gchar
#  define OPENDIR_OP(name) g_dir_open(name, 0, dummy)
#  define DIRGETNEXT_OP(dir) g_dir_read_name(dir)
#  define GETFNAME_OP(file) (file);
#  define CLOSEDIR_OP(dir) g_dir_close(dir)
#endif

static void init_xml_names(void) {
	xml_ns_t* xmlpi_xml_ns;
	guint i;
	DIRECTORY_T* dir;
	const FILE_T* file;
	const gchar* filename;
	gchar* dirname;

#if GLIB_MAJOR_VERSION >= 2
	GError** dummy = g_malloc(sizeof(GError *));
	*dummy = NULL;
#endif

	xmpli_names = g_hash_table_new(g_str_hash,g_str_equal);
	media_types = g_hash_table_new(g_str_hash,g_str_equal);

	unknown_ns.elements = xml_ns.elements = g_hash_table_new(g_str_hash,g_str_equal);
	unknown_ns.attributes = xml_ns.attributes = g_hash_table_new(g_str_hash,g_str_equal);

	xmlpi_xml_ns = xml_new_namespace(xmpli_names,"xml","version","encoding","standalone",NULL);

	g_hash_table_destroy(xmlpi_xml_ns->elements);
	xmlpi_xml_ns->elements = NULL;


	dirname = get_persconffile_path("dtds", FALSE);

	if (test_for_directory(dirname) != EISDIR) {
		/* Although dir isn't a directory it may still use memory */
		g_free(dirname);
		dirname = get_datafile_path("dtds");
	}

	if (test_for_directory(dirname) == EISDIR) {

	    if ((dir = OPENDIR_OP(dirname)) != NULL) {
	        while ((file = DIRGETNEXT_OP(dir)) != NULL) {
	            guint namelen;
	            filename = GETFNAME_OP(file);

	            namelen = strlen(filename);
	            if ( namelen > 4 && ( g_strcasecmp(filename+(namelen-4),".dtd")  == 0 ) ) {
	                GString* errors = g_string_new("");
	                GString* preparsed = dtd_preparse(dirname, filename, errors);
	                dtd_build_data_t* dtd_data;

	                if (errors->len) {
	                    report_failure("Dtd Preparser in file %s%c%s: %s",dirname,G_DIR_SEPARATOR,filename,errors->str);
	                    continue;
	                }

	                dtd_data = dtd_parse(preparsed);

	                g_string_free(preparsed,TRUE);

	                if (dtd_data->error->len) {
	                    report_failure("Dtd Parser in file %s%c%s: %s",dirname,G_DIR_SEPARATOR,filename,dtd_data->error->str);
	                    destroy_dtd_data(dtd_data);
	                    continue;
	                }

	                register_dtd(dtd_data,errors);

	                if (errors->len) {
	                    report_failure("Dtd Registration in file: %s%c%s: %s",dirname,G_DIR_SEPARATOR,filename,errors->str);
	                    g_string_free(errors,TRUE);
	                    continue;
	                }
	            }
	        }

	        CLOSEDIR_OP(dir);
	    }
	}

	for(i=0;i<array_length(default_media_types);i++) {
		if( ! g_hash_table_lookup(media_types,default_media_types[i]) ) {
			g_hash_table_insert(media_types,(gpointer)default_media_types[i],&xml_ns);
		}
	}

	g_hash_table_foreach(xmpli_names,add_xmlpi_namespace,"xml.xmlpi");

#if GLIB_MAJOR_VERSION >= 2
	g_free(dummy);
#endif
}

static void apply_prefs(void) {
    if (pref_heuristic) {
        heur_dissector_add("http", dissect_xml_heur, xml_ns.hf_tag);
        heur_dissector_add("sip", dissect_xml_heur, xml_ns.hf_tag);
        heur_dissector_add("media", dissect_xml_heur, xml_ns.hf_tag);
    }
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
		{ &xml_ns.hf_cdata, {"Unknown", "xml.unknown", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }}
    };
	module_t* xml_module;

	hf_arr = g_array_new(FALSE,FALSE,sizeof(hf_register_info));
	ett_arr = g_array_new(FALSE,FALSE,sizeof(gint*));

	g_array_append_vals(hf_arr,hf_base,array_length(hf_base));
	g_array_append_vals(ett_arr,ett_base,array_length(ett_base));

	init_xml_names();

	xml_ns.hf_tag = proto_register_protocol("eXtensible Markup Language", "XML", xml_ns.name);

	proto_register_field_array(xml_ns.hf_tag, (hf_register_info*)hf_arr->data, hf_arr->len);
	proto_register_subtree_array((gint**)ett_arr->data, ett_arr->len);

	xml_module = prefs_register_protocol(xml_ns.hf_tag,apply_prefs);
    prefs_register_bool_preference(xml_module, "heuristic", "Use Heuristics",
                                   "Try to recognize XML for unknown media types",
                                   &pref_heuristic);

    g_array_free(hf_arr,FALSE);
    g_array_free(ett_arr,TRUE);

	register_dissector("xml", dissect_xml, xml_ns.hf_tag);

	init_xml_parser();

}

static void add_dissector_media(gpointer k, gpointer v _U_, gpointer p _U_) {
	dissector_add_string("media_type", (gchar*)k, xml_handle);
}

void
proto_reg_handoff_xml(void)
{

	xml_handle = find_dissector("xml");

	g_hash_table_foreach(media_types,add_dissector_media,NULL);

}
