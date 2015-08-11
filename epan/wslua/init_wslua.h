/*
 * init_wslua.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __INIT_WSLUA_H__
#define __INIT_WSLUA_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "register.h"
#include "ws_symbol_export.h"

WS_DLL_PUBLIC int wslua_count_plugins(void);
WS_DLL_PUBLIC void wslua_reload_plugins (register_cb cb, gpointer client_data);

typedef void (*wslua_plugin_description_callback)(const char *, const char *,
                                                  const char *, const char *,
                                                  void *);
WS_DLL_PUBLIC void wslua_plugins_get_descriptions(wslua_plugin_description_callback callback, void *user_data);
WS_DLL_PUBLIC void wslua_plugins_dump_all(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __INIT_WSLUA_H__ */
