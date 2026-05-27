/** @file
 * definitions for plugins structures
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PLUGINS_H__
#define __PLUGINS_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef void (*plugin_register_func)(void);
typedef uint32_t (*plugin_describe_func)(void);

typedef void plugins_t;

/**
 * @brief Identifies the subsystem a Wireshark plugin extends.
 */
typedef enum {
    WS_PLUGIN_EPAN,     /**< Dissector or tap plugin extending the EPAN (packet analysis) engine */
    WS_PLUGIN_WIRETAP,  /**< File format plugin extending the Wiretap capture I/O library */
    WS_PLUGIN_CODEC,    /**< Audio codec plugin used for decoding RTP or other media streams */
    WS_PLUGIN_UI        /**< User interface plugin extending the GUI (Qt or GTK) layer */
} plugin_type_e;

#define WS_PLUGIN_DESC_DISSECTOR    (1UL << 0)
#define WS_PLUGIN_DESC_FILE_TYPE    (1UL << 1)
#define WS_PLUGIN_DESC_CODEC        (1UL << 2)
#define WS_PLUGIN_DESC_EPAN         (1UL << 3)
#define WS_PLUGIN_DESC_TAP_LISTENER (1UL << 4)
#define WS_PLUGIN_DESC_DFILTER      (1UL << 5)
#define WS_PLUGIN_DESC_UI           (1UL << 6)

/**
 * @brief Initialize plugins of a specific type.
 *
 * Initializes and loads plugins based on the given type and application environment variable prefix.
 *
 * @param type The type of plugin to initialize.
 * @param app_env_var_prefix Prefix for the application environment variables.
 * @return A pointer to the initialized plugins_t structure, or NULL if no plugins are supported.
 */
WS_DLL_PUBLIC plugins_t *plugins_init(plugin_type_e type, const char* app_env_var_prefix);

typedef void (*plugin_description_callback)(const char *name, const char *version,
                                            uint32_t flags, const char *filename,
                                            void *user_data);

/**
 * @brief Retrieves descriptions of all plugins.
 *
 * @param callback Callback function to handle plugin descriptions.
 * @param user_data User data to pass to the callback function.
 */
WS_DLL_PUBLIC void plugins_get_descriptions(plugin_description_callback callback, void *user_data);

/**
 * @brief Prints the description of all plugins.
 */
WS_DLL_PUBLIC void plugins_dump_all(void);

/**
 * @brief Gets the count of all loaded plugins.
 *
 * @return The total number of loaded plugins.
 */
WS_DLL_PUBLIC int plugins_get_count(void);

/**
 * @brief Cleans up and unloads a plugin.
 *
 * @param plugins Pointer to the plugins_t structure to clean up.
 */
WS_DLL_PUBLIC void plugins_cleanup(plugins_t *plugins);

/**
 * @brief Checks if plugins are supported.
 *
 * @return true if plugins are supported, false otherwise.
 */
WS_DLL_PUBLIC bool plugins_supported(void);

/**
 * @brief Returns true if the given filename ends in .dll on Windows or .so on other platforms.
 *
 * @param filename The name of the file to check.
 * @return true if the filename ends with the appropriate extension for the platform, false otherwise.
 */
WS_DLL_PUBLIC bool is_plugin_filename(const char *filename);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PLUGINS_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
