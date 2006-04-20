/* profinet-plugin.c
 * Routines for the PROFINET plugin
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "moduleinfo.h"
#include <gmodule.h>

#include <glib.h>

/* Define version if we are not building ethereal statically */

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;
#endif

gboolean plugin_registered = FALSE;

/* XXX */
extern void proto_register_pn_io (void);
extern void proto_reg_handoff_pn_io (void);
extern void proto_register_pn_dcp (void);
extern void proto_reg_handoff_pn_dcp (void);
extern void proto_register_pn_ptcp (void);
extern void proto_reg_handoff_pn_ptcp (void);

/* Start the functions we need for the plugin stuff */

#ifndef ENABLE_STATIC

G_MODULE_EXPORT void
plugin_register(void)
{
  /* register the new protocol, protocol fields, and subtrees */
  if (plugin_registered == FALSE) { /* execute protocol initialization only once */
    proto_register_pn_io();
    proto_register_pn_dcp();
    proto_register_pn_ptcp();
	  
	plugin_registered = TRUE;
  }
}

G_MODULE_EXPORT void
plugin_reg_handoff(void){
  proto_reg_handoff_pn_io();
  proto_reg_handoff_pn_dcp();
  proto_reg_handoff_pn_ptcp();
}

#endif

/* End the functions we need for plugin stuff */

