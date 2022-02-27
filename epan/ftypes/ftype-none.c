/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ftypes-int.h>


void
ftype_register_none(void)
{

	static ftype_t none_type = {
		FT_NONE,			/* ftype */
		"FT_NONE",			/* name */
		"Label",			/* pretty_name */
		0,				/* wire_size */
		NULL,				/* new_value */
		NULL,				/* free_value */
		NULL,				/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		NULL,				/* val_to_string_repr */

		{ NULL },			/* union set_value */
		{ NULL },			/* union get_value */

		NULL,				/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* is_zero */
		NULL,				/* len */
		NULL,				/* slice */
		NULL,				/* biwise_and */
		NULL,				/* unary_minus */
	};
	ftype_register(FT_NONE, &none_type);
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
