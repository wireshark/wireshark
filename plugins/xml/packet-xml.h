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
	XML_TEXT,
	XML_COMMENT,
	XML_TAG,
	XML_CLOSEDTAG,
	XML_MARKUPDECL,
	XML_XMLPI,
	XML_CLOSE_TAG,
	XML_DOCTYPE_START,
	XML_DOCTYPE_STOP
} xml_token_type_t;

struct _xml_token_t {
	xml_token_type_t type;
	int offset;
	int len;
	xml_token_t* next;
	xml_token_t* prev;
};

extern xml_token_t* scan_tvb_for_xml_items(tvbuff_t*, gint, gint);

#endif
