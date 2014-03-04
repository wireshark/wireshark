/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
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

#include "syntax-tree.h"

static gpointer
string_new(gpointer string)
{
	return (gpointer) g_strdup((char*) string);
}

static gpointer
string_dup(gconstpointer string)
{
	return (gpointer) g_strdup((const char*) string);
}

static void
string_free(gpointer value)
{
	g_free(value);
}


void
sttype_register_string(void)
{
	static sttype_t string_type = {
		STTYPE_STRING,
		"STRING",
		string_new,
		string_free,
		string_dup
	};

	static sttype_t unparsed_type = {
		STTYPE_UNPARSED,
		"UNPARSED",
		string_new,
		string_free,
		string_dup
	};

	sttype_register(&string_type);
	sttype_register(&unparsed_type);
}
