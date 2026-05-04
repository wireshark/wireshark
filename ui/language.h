/** @file
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __LANGUAGE_H__
#define __LANGUAGE_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define USE_SYSTEM_LANGUAGE	"system"

/**
 * @brief Get the currently used language.
 *
 * @return The language code as a string.
 */
char* get_language_used(void);
/* XXX - This should be temporary until all UI preferences are in place */
/**
 * @brief Sets the language used for the application.
 *
 * @param lang The language code as a string.
 */
void set_language_used(const char* lang);

/**
 * @brief Initializes the language settings.
 */
extern void language_init(void);

/**
 * @brief Cleans up language-related resources.
 */
extern void language_cleanup(void);

/**
 * @brief Reads language preferences from a file.
 *
 * @param app_env_var_prefix Prefix for application environment variables.
 */
extern void read_language_prefs(const char* app_env_var_prefix);

/**
 * @brief Writes language preferences to a configuration file.
 *
 * @param app_env_var_prefix Prefix for application environment variables.
 * @param err_info Pointer to store error information if an error occurs.
 * @return true if successful, false otherwise.
 */
extern bool write_language_prefs(const char* app_env_var_prefix, char** err_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* language.h */
