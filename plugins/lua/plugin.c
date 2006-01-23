/*
 * plugin.c
 *
 * Ethereal's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

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
    
}

G_MODULE_EXPORT void plugin_reg_handoff(void)
{
    if (! initialized ) {
        proto_register_lua();
		initialized = 1;
	}
    
    proto_reg_handoff_lua();

}
#endif
