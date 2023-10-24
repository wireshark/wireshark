/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DFILTER_PLUGIN_H
#define DFILTER_PLUGIN_H

#include <wireshark.h>

#include <epan/dfilter/dfunctions.h>

typedef struct {
	void (*init)(void);
	void (*cleanup)(void);
} dfilter_plugin;

extern GSList *dfilter_plugins;

WS_DLL_PUBLIC
void dfilter_plugins_register(const dfilter_plugin *plugin);

void dfilter_plugins_init(void);

void dfilter_plugins_cleanup(void);

#endif /* DFILTER_PLUGIN_H */
