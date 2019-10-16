/*
 * init_wslua.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __INIT_WSLUA_H__
#define __INIT_WSLUA_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "ws_symbol_export.h"

WS_DLL_PUBLIC int wslua_count_plugins(void);
WS_DLL_PUBLIC void wslua_reload_plugins (register_cb cb, gpointer client_data);

typedef void (*wslua_plugin_description_callback)(const char *, const char *,
                                                  const char *, const char *,
                                                  void *);
WS_DLL_PUBLIC void wslua_plugins_get_descriptions(wslua_plugin_description_callback callback, void *user_data);
WS_DLL_PUBLIC void wslua_plugins_dump_all(void);
WS_DLL_PUBLIC const char *wslua_plugin_type_name(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __INIT_WSLUA_H__ */
