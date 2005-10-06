/*
 *  dtd.h
 *
 * XML dissector for ethereal 
 * DTD import declarations
 *
 * Copyright 2005, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id $
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

#ifndef _DTD_H_
#define _DTD_H_

#include <glib.h>

typedef struct _dtd_build_data_t {
	gchar* proto_name;
	gchar* media_type;
	gchar* description;
	gchar* proto_root;
	gboolean recursion;

	GPtrArray* elements;
	GPtrArray* attributes;

	GString* error;
} dtd_build_data_t;

typedef struct _dtd_token_data_t {
	gchar* text;
	gchar* location;
} dtd_token_data_t;

typedef struct _dtd_named_list_t {
	gchar* name;
	GPtrArray* list;
} dtd_named_list_t;

extern GString* dtd_preparse(const gchar* dname, const gchar* fname, GString* err);
extern dtd_build_data_t* dtd_parse(GString* s);

#endif
