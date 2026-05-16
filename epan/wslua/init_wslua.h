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
#include <epan/register.h> /* for register_cb */
#include <stdbool.h>

#include "epan/register.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Counts the number of Lua plugins.
 *
 * This function counts the total number of Lua plugins, including global scripts,
 * user scripts, and scripts specified from the command line.
 *
 * @return The total count of Lua plugins.
 */
WS_DLL_PUBLIC int wslua_count_plugins(void);

/**
 * @brief Reloads Lua plugins.
 *
 * This function reloads all Lua plugins by notifying the debugger, deregistering heuristics and protocols,
 * and reinitializing the Lua environment.
 *
 * @param cb Callback function to be called during the reload process.
 * @param client_data User data passed to the callback function.
 * @param app_env_var_prefix Prefix for application environment variables.
 * @return true if the reload was successful, false otherwise.
 */
WS_DLL_PUBLIC bool wslua_reload_plugins (register_cb cb, void *client_data, const char* app_env_var_prefix);

typedef void (*wslua_plugin_description_callback)(const char *, const char *,
                                                  const char *, const char *,
                                                  void *);

/**
 * @brief Retrieves descriptions of all loaded WSLua plugins.
 *
 * This function iterates through a list of loaded WSLua plugins and calls a provided callback function for each plugin, passing details such as the plugin's name, version, type, and filename.
 *
 * @param callback A pointer to the callback function that will be called for each plugin.
 * @param user_data A pointer to user-specific data that will be passed to the callback function.
 */
WS_DLL_PUBLIC void wslua_plugins_get_descriptions(wslua_plugin_description_callback callback, void *user_data);

/**
 * @brief Dumps all Lua plugins.
 */
WS_DLL_PUBLIC void wslua_plugins_dump_all(void);

/**
 * @brief Returns the type name of the WSLUA plugin.
 *
 * This function provides a string that identifies the type of the WSLUA plugin,
 * which is "Lua script".
 *
 * @return A constant character pointer to the string "Lua script".
 */
WS_DLL_PUBLIC const char *wslua_plugin_type_name(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __INIT_WSLUA_H__ */
