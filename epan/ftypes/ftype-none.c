
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ftypes-int.h>


void
ftype_register_none(void)
{

	static ftype_t none_type = {
		"FT_NONE",
		"label",
		0,
	};

	ftype_register(FT_NONE, &none_type);
}
