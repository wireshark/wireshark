/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "sttype-pointer.h"

#include "ftypes/ftypes.h"
#include "syntax-tree.h"
#include <epan/proto.h> // For BASE_NONE

static void
sttype_fvalue_free(gpointer value)
{
	fvalue_t *fvalue = value;

	/* If the data was not claimed with stnode_steal_data(), free it. */
	if (fvalue) {
		fvalue_free(fvalue);
	}
}

static void
pcre_free(gpointer value)
{
	ws_regex_t *pcre = value;

	/* If the data was not claimed with stnode_steal_data(), free it. */
	if (pcre) {
		ws_regex_free(pcre);
	}
}

static char *
sttype_fvalue_tostr(const void *data, gboolean pretty)
{
	const fvalue_t *fvalue = data;

	char *s, *repr;

	s = fvalue_to_string_repr(NULL, fvalue, FTREPR_DFILTER, BASE_NONE);
	if (pretty)
		repr = g_strdup(s);
	else
		repr = ws_strdup_printf("%s <%s>", s, fvalue_type_name(fvalue));
	g_free(s);
	return repr;
}

static char *
pcre_tostr(const void *data, gboolean pretty _U_)
{
	return g_strdup(ws_regex_pattern(data));
}

static char *
charconst_tostr(const void *data, gboolean pretty _U_)
{
	unsigned long num = *(const unsigned long *)data;

	if (num > 0x7f)
		goto out;

	switch (num) {
		case 0:    return g_strdup("'\\0'");
		case '\a': return g_strdup("'\\a'");
		case '\b': return g_strdup("'\\b'");
		case '\f': return g_strdup("'\\f'");
		case '\n': return g_strdup("'\\n'");
		case '\r': return g_strdup("'\\r'");
		case '\t': return g_strdup("'\\t'");
		case '\v': return g_strdup("'\\v'");
		case '\'': return g_strdup("'\\''");
		case '\\': return g_strdup("'\\\\'");
		default:
			break;
	}

	if (g_ascii_isprint(num))
		return ws_strdup_printf("'%c'", (int)num);
out:
	return ws_strdup_printf("'\\x%02lx'", num);
}

ftenum_t
sttype_pointer_ftenum(stnode_t *node)
{
	switch (node->type->id) {
		case STTYPE_FIELD:
		case STTYPE_REFERENCE:
			return ((header_field_info *)node->data)->type;
		case STTYPE_FVALUE:
			return fvalue_type_ftenum(node->data);
		default:
			break;
	}
	return FT_NONE;
}

void
sttype_register_pointer(void)
{
	static sttype_t fvalue_type = {
		STTYPE_FVALUE,
		"FVALUE",
		NULL,
		sttype_fvalue_free,
		NULL,
		sttype_fvalue_tostr
	};
	static sttype_t pcre_type = {
		STTYPE_PCRE,
		"PCRE",
		NULL,
		pcre_free,
		NULL,
		pcre_tostr
	};
	static sttype_t charconst_type = {
		STTYPE_CHARCONST,
		"CHARCONST",
		NULL,
		g_free,
		NULL,
		charconst_tostr
	};

	sttype_register(&fvalue_type);
	sttype_register(&pcre_type);
	sttype_register(&charconst_type);
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
