/* packet-xml.c
* an XML dissector for ethereal 
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>

#include "packet-xml.h"

#ifdef DEBUG_XML
static const value_string xml_token_types[] =
{
	{XML_WHITESPACE,	"white space"},
	{XML_PROPERTY,		"property"},
	{XML_COMMENT_START, "comment start"},
	{XML_COMMENT_END,   "comment end"},
	{XML_METATAG_START, "metatag start"},
	{XML_METATAG_END,   "metatag end"},
	{XML_TAG_START,		"tag start"},
	{XML_TAG_END,		"tag end"},
	{XML_CLOSE_TAG_END,	"close tag end"},
	{XML_NAME,			"name"},
	{XML_TEXT,			"text"},
	{XML_GARBLED,		"garbled"},
	{0, NULL}
};

static const value_string xml_ctx_types[] =
{
	{XML_CTX_OUT, "no_ctx"},
	{XML_CTX_COMMENT, "comment"},
	{XML_CTX_TAG, "tag"},
	{XML_CTX_METATAG, "meta-tag"},
	{XML_CTX_CLOSETAG, "close-tag"},
	{0, NULL}
};

static int hf_xml_token = -1;
static int hf_xml_token_type = -1;
static int hf_xml_ctx_type = -1;
static int ett_xml_tok = -1;

#endif /* DEBUG_XML */

static int proto_xml = -1;
static int ett_xml = -1;
static int hf_xml_metatag = -1;
static int hf_xml_tag = -1;
static int hf_xml_text = -1;

gboolean is_soap;

static proto_item* proto_tree_add_xml_item(proto_tree* tree, tvbuff_t* tvb, int offset, int len, xml_token_t* xi) {
	proto_item* pi;
	gchar* txt;
	int hfid = 0;
	
	switch (xi->type) {
		case XML_TAG_END: if (xi->ctx == XML_CTX_TAG) hfid = hf_xml_tag; break;
		case XML_METATAG_END: hfid = hf_xml_metatag; break;
		case XML_TEXT: hfid = hf_xml_text; break;
		default: break;
	}

	txt = tvb_get_string(tvb,offset,len);

	if ( hfid ) {
		pi = proto_tree_add_string_format(tree,hfid,tvb,offset,len,txt,"%s",format_text(txt, len));
	} else {
		pi = proto_tree_add_text(tree,tvb,offset,len,"%s",format_text(txt, len));
	}
	
	g_free(txt);
	
	return pi;
}


static void dissect_xml(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree) {
	xml_token_t* xml_items ;
	xml_token_t* xi;
	xml_token_t* next_xi;
	proto_item* pi = NULL;
	int curr_offset = 0;
	int curr_len = 0;
	GPtrArray* stack;
#ifdef DEBUG_XML
	proto_tree* tree2 = NULL;
#endif
	
	is_soap = FALSE;
	
#define push() { g_ptr_array_add(stack,tree); tree = proto_item_add_subtree(pi, ett_xml); }
#define pop()  { tree = g_ptr_array_remove_index(stack,stack->len - 1); }
	
	if (tree) {
		pi = proto_tree_add_item(tree, proto_xml, tvb, 0, tvb->length, FALSE);
		
#ifdef DEBUG_XML
		tree = proto_item_add_subtree(pi, ett_xml);
		
		pi = proto_tree_add_item(tree, proto_xml, tvb, 0, tvb->length, FALSE);
		tree2 = proto_item_add_subtree(pi, ett_xml);
#else
		tree = proto_item_add_subtree(pi, ett_xml);
#endif /* DEBUG_XML */
		
		xml_items = scan_tvb_for_xml_items(tvb, 0, tvb->length);
		
		stack = g_ptr_array_new();
		
		for (xi = xml_items; xi; xi = xi->next) {
			
#ifdef DEBUG_XML
			pi = proto_tree_add_item(tree2,hf_xml_token,tvb,xi->offset,xi->len,FALSE);
			pt = proto_item_add_subtree(pi, ett_xml);
			proto_tree_add_uint(pt,hf_xml_token_type,tvb,0,0,xi->type);
			proto_tree_add_uint(pt,hf_xml_ctx_type,tvb,0,0,xi->ctx);
			proto_tree_add_text(pt,tvb,0,0,"[%i,%i] (%i,%i): '%s'",curr_offset,curr_len,xi->offset,xi->len,xi->text);
#endif /* DEBUG_XML */
			
			switch (xi->type) {
				case XML_COMMENT_START:
				case XML_METATAG_START:
				case XML_CLOSE_TAG_START:
				case XML_TAG_START:
					curr_offset = xi->offset;
				case XML_PROPERTY:
				case XML_NAME:
					curr_len += xi->len;
					break;
				case XML_WHITESPACE:
					if (xi->ctx == XML_CTX_OUT && curr_len == 0) {
						curr_offset += xi->len;
					} else {
						curr_len += xi->len;						
					}
					break;
				case XML_COMMENT_END:
				case XML_METATAG_END:
				case XML_CLOSE_TAG_END:
				case XML_TEXT:
					curr_len += xi->len;
					proto_tree_add_xml_item(tree,tvb,curr_offset,curr_len,xi);
					curr_offset = curr_offset + curr_len;
					curr_len = 0;
					break;
				case XML_TAG_END:
					curr_len += xi->len;
					if (xi->ctx == XML_CTX_CLOSETAG) pop();
					pi = proto_tree_add_xml_item(tree,tvb,curr_offset,curr_len,xi);
					if (xi->ctx == XML_CTX_TAG) push();
					curr_offset = curr_offset + curr_len;
					curr_len = 0;
					break;
				case XML_GARBLED:
					break;
			}
			
		}
		
		for (xi = xml_items; xi; xi = next_xi) {
			next_xi = xi->next;
			
			if (xi->text) g_free(xi->text);
			g_free(xi);
		}
		
		g_ptr_array_free(stack,FALSE);
	}
	
}

void
proto_register_xml(void)
{
	static hf_register_info hf[] = {
#ifdef DEBUG_XML
    { &hf_xml_token,
	{ "XML Token",
		"xml.token", FT_STRING, BASE_NONE,NULL,0x0,
		"An XML token", HFILL }},
    { &hf_xml_token_type,
	{ "XML Token Type",
		"xml.token.type", FT_UINT32, BASE_DEC,xml_token_types,0x0,
		"the type of an XML token", HFILL }},
	{ &hf_xml_ctx_type,
	{ "XML Context Type",
			"xml.ctx.type", FT_UINT32, BASE_DEC,xml_ctx_types,0x0,
			"the context of an XML token", HFILL }},
#endif /* DEBUG_XML */
	{ &hf_xml_metatag,
	{ "XML Meta Tag",
		"xml.meta_tag", FT_STRING, BASE_NONE, NULL, 0x0,
		"XML Meta Tag", HFILL }},
	{ &hf_xml_tag,
	{ "XML Tag",
		"xml.tag", FT_STRING, BASE_NONE, NULL, 0x0,
		"XML Tag", HFILL }},
	{ &hf_xml_text,
	{ "XML Text",
		"xml.text", FT_STRING, BASE_NONE, NULL, 0x0,
		"Text in XML", HFILL }}
	};
	
	static gint *ett[] = {
#ifdef DEBUG_XML
		&ett_xml_tok,
#endif /* DEBUG_XML */
		&ett_xml
	};
	
	proto_xml = proto_register_protocol("eXtensible Markup Language", "XML", "xml");
	proto_register_field_array(proto_xml, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("xml", dissect_xml, proto_xml);

}

void
proto_reg_handoff_xml(void)
{
	dissector_handle_t xml_handle;
	
	xml_handle = find_dissector("xml");

	dissector_add_string("media_type", "text/xml", xml_handle);
}
