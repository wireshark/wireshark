/* $Id: sttype-pointer.c,v 1.1 2001/02/01 20:21:18 gram Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
	};
	static sttype_t fvalue_type = {
		STTYPE_FVALUE,
		"FVALUE",
		NULL,
		NULL,
	};

	sttype_register(&field_type);
	sttype_register(&fvalue_type);
}
