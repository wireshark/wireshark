/* packet-xml.h
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

#ifndef __XML_H_
#define __XML_H_
#include <epan/tvbuff.h>

typedef struct _xml_token_t xml_token_t;

typedef enum _xml_token_type_t {
	XML_WHITESPACE,
	XML_PROPERTY,
	XML_COMMENT_START,
	XML_COMMENT_END,
	XML_TAG_START,
	XML_TAG_END,
	XML_METATAG_START,
	XML_METATAG_END,
	XML_CLOSE_TAG_START,
	XML_CLOSE_TAG_END,
	XML_NAME,
	XML_TEXT,
	XML_GARBLED
} xml_token_type_t;

typedef enum _xml_context_t {
	XML_CTX_OUT,
	XML_CTX_COMMENT,
	XML_CTX_TAG,
	XML_CTX_METATAG,
	XML_CTX_CLOSETAG
} xml_context_t;

struct _xml_token_t {
	xml_token_type_t type;
	xml_context_t ctx;
	char* text;
	int offset;
	int len;
	xml_token_t* next;
	xml_token_t* prev;
};

extern xml_token_t* scan_tvb_for_xml_items(tvbuff_t*, gint, gint);

#endif
