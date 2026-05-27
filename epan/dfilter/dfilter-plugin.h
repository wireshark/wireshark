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

/**
 * @brief Describes a display filter plugin, providing lifecycle callbacks for initialization and cleanup.
 */
typedef struct {
    void (*init)(void);    /**< Called to initialize the plugin and register its components. */
    void (*cleanup)(void); /**< Called to clean up and release any resources registered by the plugin. */
} dfilter_plugin;

/** Global list of registered display filter plugins. */
extern GSList *dfilter_plugins;

/**
 * @brief Registers a DFilter plugin.
 *
 * @param plugin Pointer to the dfilter_plugin structure to be registered.
 */
WS_DLL_PUBLIC
void dfilter_plugins_register(const dfilter_plugin *plugin);

 /**
  * @brief Initialize all registered DFilter plugins.
  *
  * This function iterates through a list of DFilter plugins and calls their init functions to set up any necessary resources or configurations.
  */

void dfilter_plugins_init(void);

/**
 * @brief Cleans up all registered DFilter plugins.
 *
 * This function iterates through a list of DFilter plugins, invoking each plugin's cleanup method,
 * and then frees the list itself.
 */
void dfilter_plugins_cleanup(void);

#endif /* DFILTER_PLUGIN_H */
