/* mate_plugin.c
* MATE -- Meta Analysis Tracing Engine
*
* Copyright 2004, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
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
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* this file is used temporarily to buid it as a plugin */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugins/plugin_api.h"
#include "moduleinfo.h"
#include <gmodule.h>
#include "plugins/plugin_api_defs.h"


/* these two are in packet-mate.c */
void proto_register_mate(void);
void proto_reg_handoff_mate(void);
static gboolean initialized = FALSE;

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;

G_MODULE_EXPORT void plugin_init(plugin_address_table_t *pat _U_ ) {
	/* initialise the table of pointers needed in Win32 DLLs */
	plugin_address_table_init(pat);
	
	/* register the new protocol, protocol fields, and subtrees */
	if (! initialized ) { /* execute protocol initialization only once */
		proto_register_mate();
		initialized = 1;
	}
}

G_MODULE_EXPORT void plugin_reg_handoff(void)
{
	proto_reg_handoff_mate();
}
#endif
