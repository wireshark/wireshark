/* plugins.h
 * definitions for plugins structures
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

#ifndef __PLUGINS_H__
#define __PLUGINS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include <gmodule.h>

#include "packet.h"

typedef struct _plugin {
    GModule	*handle;          /* handle returned by g_module_open */
    gchar       *name;            /* plugin name */
    gchar       *version;         /* plugin version */
    void (*register_protoinfo)(void); /* routine to call to register protocol information */
    void (*reg_handoff)(void);    /* routine to call to register dissector handoff */
    void (*register_tap_listener)(void);   /* routine to call to register tap listener */
    void (*register_wtap_module)(void);  /* routine to call to register a wiretap module */
    void (*register_codec_module)(void);  /* routine to call to register a codec */
    struct _plugin *next;         /* forward link */
} plugin;

WS_VAR_IMPORT plugin *plugin_list;

extern void init_plugins(void);
extern void register_all_plugin_registrations(void);
extern void register_all_plugin_handoffs(void);
extern void register_all_plugin_tap_listeners(void);
extern void register_all_wiretap_modules(void);
extern void register_all_codecs(void);
extern void plugins_dump_all(void);

typedef struct _wslua_plugin {
    gchar       *name;            /**< plugin name */
    gchar       *version;         /**< plugin version */
    gchar       *filename;        /**< plugin filename */
    struct _wslua_plugin *next;
} wslua_plugin;

WS_VAR_IMPORT wslua_plugin *wslua_plugin_list;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PLUGINS_H__ */
