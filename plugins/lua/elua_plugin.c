/*
 * plugin.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
#ifdef HAVE_LUA_5_1
#define PACKAGE "lua_plugin_5.1"
#else
#define PACKAGE "lua_plugin_5.0.2"
#endif

#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */
#ifdef HAVE_LUA_5_1
#define VERSION "510.0.1"
#else
#define VERSION "502.0.1"
#endif


#include <gmodule.h>
#endif
#include <glib.h>

void proto_register_lua(void);

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
}
#endif
