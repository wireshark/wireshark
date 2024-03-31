/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __INIT_WSLUA_H__
#define __INIT_WSLUA_H__

#include "ws_symbol_export.h"

#include <wsutil/plugins.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC int wslua_count_plugins(void);
WS_DLL_PUBLIC void wslua_reload_plugins (register_cb cb, void *client_data);

WS_DLL_PUBLIC void wslua_plugins_get_descriptions(plugin_description_callback callback, void *user_data);
WS_DLL_PUBLIC void wslua_plugins_dump_all(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __INIT_WSLUA_H__ */
