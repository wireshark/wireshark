%option noyywrap
%option nounput 
%option caseless

%{

	/* xml_lexer.l
	* an XML dissector for ethereal 
	* lexical analyzer for XML
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

	static guint8* extracted = NULL;
	static gint offset;
	static gint text_offset;
	static gint len;
	
	tvbuff_t* tvb;
	proto_item* pi;
	proto_tree* tree;
	GPtrArray* stack;
	static int ett_xml;
	static int proto_xml;

#define YY_INPUT(buff,result,max_size) \
	( (result) = tvb_yyinput((buff),(max_size)) )

#define ECHO ; 
	
	static void add_xml_item(xml_token_type_t, guint);
	static int tvb_yyinput(char*, guint);
	
%}
xmlpi_start "<?"
xmlpi_end "?>"

comment_start <!--
comment_end  -->

markupdecl_start "<!"
closetag_start "</"
tag_start "<"

tag_end >
closedtag_end "/>"
open_brace "["

dtd_doctype_stop "]"[:blank:]*>

whitespace [[:blank:]\r\n]+
text_start ([^<[:blank:]\r\n]|[^<])
text_stop <

%START OUT COMMENT TAG CLOSE_TAG XMLPI DOCTYPE MARKUPDECL TEXT
%%

<OUT>{whitespace}			{ text_offset = offset - yyleng; add_xml_item(XML_WHITESPACE, yyleng); }
<OUT>{dtd_doctype_stop}		{ text_offset = offset - yyleng; add_xml_item(XML_DOCTYPE_STOP, yyleng); }

<OUT>{text_start}			{ text_offset = offset - yyleng; BEGIN TEXT; }
<TEXT>{text_stop}			{ add_xml_item(XML_TEXT, --offset - text_offset ); BEGIN OUT; }

<OUT>{comment_start}		{ text_offset = offset - yyleng; BEGIN COMMENT; }
<COMMENT>{comment_end}		{ add_xml_item(XML_COMMENT, offset - text_offset); BEGIN OUT; }

<OUT>{closetag_start}		{ text_offset = offset - yyleng ; BEGIN CLOSE_TAG; }
<CLOSE_TAG>{tag_end}		{ add_xml_item(XML_CLOSE_TAG, offset - text_offset ); BEGIN OUT; }

<OUT>{xmlpi_start}			{ text_offset = offset - yyleng; BEGIN XMLPI; }
<XMLPI>{xmlpi_end}			{ add_xml_item(XML_XMLPI, offset - text_offset); BEGIN OUT; }

<OUT>{markupdecl_start}		{ text_offset = offset - yyleng -1; BEGIN MARKUPDECL; }
<MARKUPDECL>{open_brace}	{ add_xml_item(XML_DOCTYPE_START, offset - text_offset); BEGIN OUT; }
<MARKUPDECL>{tag_end}		{ add_xml_item(XML_MARKUPDECL,  offset - text_offset); BEGIN OUT; }

<OUT>{tag_start}			{ text_offset = offset - yyleng -1; BEGIN TAG; }
<TAG>{closedtag_end}		{ add_xml_item(XML_CLOSEDTAG, offset - text_offset); BEGIN OUT; }
<TAG>{tag_end}				{ add_xml_item(XML_TAG, offset - text_offset); BEGIN OUT; }

%%

static void add_xml_item(xml_token_type_t type, guint the_len) {
	switch (type) {
		case XML_WHITESPACE:
			break;
		case XML_CLOSEDTAG:
		case XML_TEXT:
		case XML_MARKUPDECL:
		case XML_XMLPI:
		case XML_COMMENT:
			pi = proto_tree_add_xml_item(tree,tvb,type,text_offset,the_len);
			break;
		case XML_DOCTYPE_START:
		case XML_TAG:  
			pi = proto_tree_add_xml_item(tree,tvb,type,text_offset,the_len);
			g_ptr_array_add(stack,tree);
			tree = proto_item_add_subtree(pi, ett_xml);
			break;
		case XML_CLOSE_TAG:
		case XML_DOCTYPE_STOP: 
			pi = proto_tree_add_xml_item(tree,tvb,type,text_offset,the_len); 
			if ( stack->len ) 
				tree = g_ptr_array_remove_index(stack,stack->len - 1);
				break;						
	}	
}

static int tvb_yyinput(char* buff, guint max_len _U_) {
	
	if ( offset < len ) {
		buff[0] = extracted[offset];
		offset++;
		return 1;
	} else {
		return YY_NULL;
	}
}

extern void xml_lexer_init(int proto_hfid, int ett) {
	
	proto_xml = proto_hfid;
	ett_xml = ett;
};

extern void dissect_xml(tvbuff_t* the_tvb, packet_info* pinfo _U_, proto_tree* the_tree) {

	if (the_tree) {
		
		tree = the_tree;
		tvb = the_tvb;
		text_offset = offset = 0;
		len = tvb_length(tvb);
		extracted = tvb_memdup(tvb,offset,len);
		stack = g_ptr_array_new();

		pi = proto_tree_add_item(tree, proto_xml, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(pi, ett_xml);
				
		BEGIN OUT;
		yylex();
		yyrestart(NULL);
		
		g_free(extracted);
		g_ptr_array_free(stack,FALSE);
		
	}
}
