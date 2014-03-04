/*
 *  dtd.h
 *
 * XML dissector for Wireshark
 * DTD import declarations
 *
 * Copyright 2005, Luis E. Garcia Ontanon <luis@ontanon.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _DTD_H_
#define _DTD_H_

#include <glib.h>
#include <stdlib.h> /* exit() */

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
