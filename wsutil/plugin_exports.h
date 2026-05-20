/** @file
 * declarations of variables and functions exported by plugins
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#ifndef WS_BUILD_DLL
#error "WS_BUILD_DLL isn't defined when building this plugin"
#endif

#include <ws_symbol_export.h>
#include <stdint.h>

/** @brief Version string of this plugin (e.g. "1.0.0"). */
WS_DLL_PUBLIC const char plugin_version[];

/** @brief Major version of Wireshark this plugin was compiled against. */
WS_DLL_PUBLIC const int plugin_want_major;

/** @brief Minor version of Wireshark this plugin was compiled against. */
WS_DLL_PUBLIC const int plugin_want_minor;


/**
 * @brief Registers the plugin's protocols, dissectors, or other components with Wireshark.
 */
WS_DLL_PUBLIC void plugin_register(void);

/**
 * @brief Returns a bitmask describing the capabilities/type of this plugin.
 *
 * @return A @c uint32_t bitmask of @c WS_PLUGIN_DESC_* flags (e.g.
 *         @c WS_PLUGIN_DESC_DISSECTOR, @c WS_PLUGIN_DESC_FILE_TYPE,
 *         @c WS_PLUGIN_DESC_CODEC, @c WS_PLUGIN_DESC_TAP_LISTENER).
 */
WS_DLL_PUBLIC uint32_t plugin_describe(void);
