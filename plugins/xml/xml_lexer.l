%option noyywrap
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

	
#include "packet-xml.h"
	
	static guint8* extracted = NULL;
	static gint offset;
	static gint last_offset;
	static gint len;
	xml_token_t* head;
	xml_token_t* tail;

#define YY_INPUT(buff,result,max_size) ( (result) = tvb_yyinput((buff),(max_size)) )
#define ECHO {add_xml_item(XML_GARBLED,XML_CTX_OUT, yyleng, yytext); return 0;} 
	
	static void add_xml_item(xml_token_type_t type, xml_context_t ctx, gint len, guint8* text);
	static int tvb_yyinput(char* buff, guint max_len);
	
%}
property_dq [A-Za-z][_A-Za-z0-9:]*=["][^\"]*["]
property_sq [A-Za-z][_A-Za-z0-9:]*='[^\']*'
property_nq [A-Za-z][_A-Za-z0-9:]*=[_A-Za-z0-9]+
metatag_start "<?"
metatag_end "?>"
comment_start "<!--"
comment_end  "-->"
closetag_start "</"
tag_start "<"
tag_end ">"
closedtag_end "/>"
name [A-Za-z][_A-Za-z0-9:]*
whitespace [ \t\r\n]+
text [^<]*
%START COMMENT TAG CLOSE_TAG META_TAG OUT
%%
<OUT>{comment_start}		{ add_xml_item(XML_COMMENT_START, XML_CTX_COMMENT, yyleng, yytext); BEGIN COMMENT;}
<COMMENT>{comment_end}		{ add_xml_item(XML_COMMENT_END, XML_CTX_COMMENT, yyleng, yytext); BEGIN OUT; }
<COMMENT>{text}				add_xml_item(XML_TEXT, XML_CTX_COMMENT, yyleng, yytext);
<COMMENT>{tag_start}		add_xml_item(XML_TEXT, XML_CTX_COMMENT, yyleng, yytext);

<OUT>{closetag_start}		{ add_xml_item(XML_CLOSE_TAG_START, XML_CTX_CLOSETAG, yyleng, yytext); BEGIN CLOSE_TAG; }
<CLOSE_TAG>{name}			add_xml_item(XML_NAME, XML_CTX_CLOSETAG, yyleng, yytext);
<CLOSE_TAG>{whitespace}		add_xml_item(XML_WHITESPACE, XML_CTX_CLOSETAG, yyleng,yytext);
<CLOSE_TAG>{tag_end}		{ add_xml_item(XML_TAG_END, XML_CTX_CLOSETAG, yyleng, yytext); BEGIN OUT; }

{metatag_start}		{ add_xml_item(XML_METATAG_START, XML_CTX_METATAG, yyleng, yytext); BEGIN META_TAG; }
<META_TAG>{property_dq}		add_xml_item(XML_PROPERTY, XML_CTX_METATAG, yyleng, yytext);
<META_TAG>{property_sq}		add_xml_item(XML_PROPERTY, XML_CTX_METATAG, yyleng, yytext);
<META_TAG>{property_nq}		add_xml_item(XML_PROPERTY, XML_CTX_METATAG, yyleng, yytext);
<META_TAG>{whitespace}		add_xml_item(XML_WHITESPACE,  XML_CTX_METATAG, yyleng, yytext);
<META_TAG>{name}			add_xml_item(XML_NAME,  XML_CTX_METATAG, yyleng, yytext);
<META_TAG>{metatag_end}		{ add_xml_item(XML_METATAG_END,  XML_CTX_METATAG, yyleng,yytext); BEGIN OUT; }

<OUT>{tag_start}			{ add_xml_item(XML_TAG_START, XML_CTX_TAG, yyleng, yytext); BEGIN TAG; }
<TAG>{property_dq}			add_xml_item(XML_PROPERTY, XML_CTX_TAG, yyleng, yytext);
<TAG>{property_sq}			add_xml_item(XML_PROPERTY, XML_CTX_TAG, yyleng, yytext);
<TAG>{property_nq}			add_xml_item(XML_PROPERTY, XML_CTX_TAG, yyleng, yytext);
<TAG>{name}					add_xml_item(XML_NAME, XML_CTX_TAG, yyleng, yytext);
<TAG>{whitespace}			add_xml_item(XML_WHITESPACE, XML_CTX_TAG, yyleng, yytext);
<TAG>{closedtag_end}		{add_xml_item(XML_CLOSE_TAG_END, XML_CTX_TAG, yyleng, yytext); BEGIN OUT; }
<TAG>{tag_end}				{add_xml_item(XML_TAG_END,  XML_CTX_TAG, yyleng, yytext); BEGIN OUT; }

<OUT>{whitespace}			add_xml_item(XML_WHITESPACE,  XML_CTX_OUT, yyleng, yytext);
<OUT>{text}					add_xml_item(XML_TEXT,  XML_CTX_OUT, yyleng, yytext); 
%%

static void add_xml_item(xml_token_type_t type, xml_context_t ctx, gint the_len, guint8* text) {
	xml_token_t* xi = g_malloc(sizeof(xml_token_t));
	
	xi->type = type;
	xi->ctx = ctx;
	xi->offset = last_offset;
	xi->len = the_len;
	xi->text = text != NULL ? g_strdup(text) : NULL;
	xi->next = NULL;
	xi->prev = tail;
	
	last_offset += the_len;
		
	if (!head) head = xi;
	
	if (!tail) {
		tail = xi;
	} else {
		tail->next = xi;
	}
	
	tail = xi;
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

extern xml_token_t* scan_tvb_for_xml_items(tvbuff_t* tvb, gint the_offset, gint the_len) {
	
	offset = the_offset;
	last_offset = the_offset;
	len = the_len;
	extracted = tvb_memdup(tvb,offset,len);
	
	head = NULL;
	tail = NULL;
	
	yylex();
	
	yyrestart(NULL);
	
	return head;
}
	