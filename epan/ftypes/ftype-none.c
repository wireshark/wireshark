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
		NULL,				/* copy_value */
		NULL,				/* free_value */
		NULL,				/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		NULL,				/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */

		{ NULL },			/* union set_value */
		{ NULL },			/* union get_value */

		NULL,				/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* is_zero */
		NULL,				/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		NULL,				/* biwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	ftype_register(FT_NONE, &none_type);
}

void
ftype_register_pseudofields_none(int proto)
{
	static int hf_ft_none;

	static hf_register_info hf_ftypes[] = {
		{ &hf_ft_none,
		    { "FT_NONE", "_ws.ftypes.none",
			FT_NONE, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
	};

	proto_register_field_array(proto, hf_ftypes, array_length(hf_ftypes));
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
