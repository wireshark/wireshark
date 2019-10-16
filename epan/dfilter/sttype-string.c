/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

	static sttype_t charconst_type = {
		STTYPE_CHARCONST,
		"CHARCONST",
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
	sttype_register(&charconst_type);
	sttype_register(&unparsed_type);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
