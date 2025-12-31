/** @file
 * Plugin interface for Qt-based UI
 * 2025 Michael Mann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _UI_QT_PLUGIN_H_
#define _UI_QT_PLUGIN_H_

#include "ws_symbol_export.h"
#include "ws_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    void (*register_qtui_module)(void);  /* routine to call to register a Qt-based UI plugin */
} qtui_plugin;

/**
 * @brief Register a (Qt-based) UI plugin with the system.
 *
 * Adds the specified (Qt-based) UI plugin to the internal registry, enabling support
 * for additional UI functionality. This function is typically
 * called in junction with a plugin based dissector to display its data.
 *
 * @param plug Pointer to a `qtui_plugin` structure describing the plugin.
 */
WS_DLL_PUBLIC void uiqt_register_plugin(const qtui_plugin* plug);

/**
 * @brief Initialize all UI plugins.
 *
 * Invokes the registration routines for all supported (Qt-based) UI plugins.
 * This function should be called during application startup.
 *
 * @param app_env_var_prefix The prefix for the application environment variable used to get plugin directory.
 */
WS_DLL_PUBLIC void uiqt_plugin_init(const char* app_env_var_prefix);

/**
 * @brief Clean up all registered plugins.
 *
 * Releases resources associated with (Qt-based) UI plugins.
 * This function is typically called during shutdown
 */
WS_DLL_PUBLIC void uiqt_plugin_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _UI_QT_PLUGIN_H_ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
