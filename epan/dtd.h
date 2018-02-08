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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _DTD_H_
#define _DTD_H_

#include <glib.h>
#include <stdlib.h> /* exit() */
#include "ws_attributes.h"

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

typedef struct _dtd_preparse_scanner_state Dtd_PreParse_scanner_state_t;

extern GString* dtd_preparse(const gchar* dname, const gchar* fname, GString* err);
extern dtd_build_data_t* dtd_parse(GString* s);
extern const gchar* dtd_location(Dtd_PreParse_scanner_state_t* state);

#endif
