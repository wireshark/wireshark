/* init_wslua.h
 * definitions for wslua plugins structures
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

#ifndef __INIT_WSLUA_H__
#define __INIT_WSLUA_H__

#include <glib.h>

typedef struct _wslua_plugin {
    gchar       *name;            /* plugin name */
    gchar       *version;         /* plugin version */
    struct _wslua_plugin *next;
} wslua_plugin;

WS_VAR_IMPORT wslua_plugin *wslua_plugin_list;

#endif /* __INIT_WSLUA_H__ */
