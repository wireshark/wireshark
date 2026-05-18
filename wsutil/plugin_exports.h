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

WS_DLL_PUBLIC const char plugin_version[];
WS_DLL_PUBLIC const int plugin_want_major;
WS_DLL_PUBLIC const int plugin_want_minor;

WS_DLL_PUBLIC void plugin_register(void);
WS_DLL_PUBLIC uint32_t plugin_describe(void);
