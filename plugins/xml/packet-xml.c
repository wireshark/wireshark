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

#include "packet-xml.h"

static int proto_xml = -1;

static int ett_xml = -1;

static int hf_xml_pi = -1;
static int hf_xml_markup_decl = -1;
static int hf_xml_tag = -1;
static int hf_xml_text = -1;

extern proto_item* proto_tree_add_xml_item(proto_tree* tree, tvbuff_t* tvb,
										   xml_token_type_t type, guint offset, guint len) {
	proto_item* pi;
	gchar* txt;
	int hfid;
	
	switch (type) {
		case XML_TAG:   hfid = hf_xml_tag; break;
		case XML_MARKUPDECL:	hfid = hf_xml_markup_decl; break;
		case XML_XMLPI: hfid = hf_xml_pi; break;
		case XML_TEXT: hfid = hf_xml_text; break;
		default: hfid = 0; break;
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

void
proto_register_xml(void)
{
	static hf_register_info hf[] = {
	{ &hf_xml_pi,
	{ "XML Processing Instruction",
		"xml.pi", FT_STRING, BASE_NONE, NULL, 0x0,
		"XML Processing Instruction", HFILL }},
	{ &hf_xml_markup_decl,
	{ "XML Markup Declaration",
		"xml.markrp_decl", FT_STRING, BASE_NONE, NULL, 0x0,
		"XML Markup Declaration", HFILL }},
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

	xml_lexer_init(proto_xml,ett_xml);
}
