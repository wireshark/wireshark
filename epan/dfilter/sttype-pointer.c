/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "ftypes/ftypes.h"
#include "ftypes/ftypes-int.h"
#include "syntax-tree.h"

static void
fvalue_free(gpointer value)
{
	fvalue_t *fvalue = (fvalue_t*)value;

	/* If the data was not claimed with stnode_steal_data(), free it. */
	if (fvalue) {
		FVALUE_FREE(fvalue);
	}
}

static void
pcre_free(gpointer value)
{
	GRegex	*pcre = (GRegex*)value;

	/* If the data was not claimed with stnode_steal_data(), free it. */
	if (pcre) {
		/*
		 * They're reference-counted, so just drop the reference
		 * count; it'll get freed when the reference count drops
		 * to 0.
		 */
		g_regex_unref(pcre);
	}
}

static char *
fvalue_tostr(const void *data)
{
	fvalue_t *fvalue = (fvalue_t*)data;

	char *s, *repr;

	s = fvalue_to_string_repr(NULL, fvalue, FTREPR_DFILTER, BASE_NONE);
	repr = g_strdup_printf("%s[%s]", fvalue_type_name(fvalue), s);
	g_free(s);
	return repr;
}

static char *
field_tostr(const void *data)
{
	header_field_info *hfinfo = (header_field_info *)data;

	return g_strdup(hfinfo->abbrev);
}

static char *
pcre_tostr(const void *data)
{
	const GRegex *pcre = (const GRegex *)data;

	return g_strdup(g_regex_get_pattern(pcre));
}

void
sttype_register_pointer(void)
{
	static sttype_t field_type = {
		STTYPE_FIELD,
		"FIELD",
		NULL,
		NULL,
		NULL,
		field_tostr
	};
	static sttype_t fvalue_type = {
		STTYPE_FVALUE,
		"FVALUE",
		NULL,
		fvalue_free,
		NULL,
		fvalue_tostr
	};
	static sttype_t pcre_type = {
		STTYPE_PCRE,
		"PCRE",
		NULL,
		pcre_free,
		NULL,
		pcre_tostr
	};

	sttype_register(&field_type);
	sttype_register(&fvalue_type);
	sttype_register(&pcre_type);
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
