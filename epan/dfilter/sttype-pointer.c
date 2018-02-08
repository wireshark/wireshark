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
#include "syntax-tree.h"

void
sttype_register_pointer(void)
{
	static sttype_t field_type = {
		STTYPE_FIELD,
		"FIELD",
		NULL,
		NULL,
		NULL
	};
	static sttype_t fvalue_type = {
		STTYPE_FVALUE,
		"FVALUE",
		NULL,
		NULL,
		NULL
	};

	sttype_register(&field_type);
	sttype_register(&fvalue_type);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
