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
string_dup(gconstpointer string)
{
	return g_strdup(string);
}

static void
string_free(gpointer value)
{
	g_free(value);
}

static char *
string_tostr(const void *data, gboolean pretty _U_)
{
	return g_strdup(data);
}


void
sttype_register_string(void)
{
	static sttype_t string_type = {
		STTYPE_STRING,
		"STRING",
		NULL,
		string_free,
		string_dup,
		string_tostr
	};

	static sttype_t unparsed_type = {
		STTYPE_UNPARSED,
		"UNPARSED",
		NULL,
		string_free,
		string_dup,
		string_tostr
	};

	static sttype_t literal_type = {
		STTYPE_LITERAL,
		"LITERAL",
		NULL,
		string_free,
		string_dup,
		string_tostr
	};

	sttype_register(&string_type);
	sttype_register(&unparsed_type);
	sttype_register(&literal_type);
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
