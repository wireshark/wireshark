/* plugins.h
 * definitions for plugins structures
 *
 * $Id: plugins.h,v 1.6 2001/01/28 21:17:28 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1999 Gerald Combs
 *
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

#ifndef __PLUGINS_H__
#define __PLUGINS_H__

#include <glib.h>
#include <gmodule.h>

#include "dfilter.h"
#include "packet.h"
#include "prefs.h"

typedef struct _plugin {
    GModule	*handle;          /* handle returned by dlopen */
    gchar       *name;            /* plugin name */
    gchar       *version;         /* plugin version */
    void (*reg_handoff)(void);    /* routine to call to register dissector handoff */
    struct _plugin *next;         /* forward link */
} plugin;

extern plugin *plugin_list;

void init_plugins(const char *);
void register_all_plugin_handoffs(void);

#endif /* __PLUGINS_H__ */
