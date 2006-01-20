
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef ENABLE_STATIC
#ifdef PACKAGE
#undef PACKAGE
#endif

/* Name of package */
#define PACKAGE "lua_plugin"

#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */
#define VERSION "0.0.0"


#include <gmodule.h>
#endif

void proto_register_lua(void);
void proto_reg_handoff_lua(void);

static gboolean initialized = FALSE;

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;

G_MODULE_EXPORT void plugin_register(void) {
	
	if (! initialized ) {
        proto_register_lua();
		initialized = 1;
	}
}

G_MODULE_EXPORT void plugin_reg_handoff(void)
{
    proto_reg_handoff_lua();
}
#endif
