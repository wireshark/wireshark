/** @file
 *
 * Storage of profile information
 * Stig Bjorlykke <stig@bjorlykke.org>, 2008
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PROFILE_H__
#define __PROFILE_H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Describes a single Wireshark configuration profile and its associated settings.
 */
typedef struct {
    char *name;                  /**< Display name of the profile. */
    char *reference;             /**< Reference identifier or path for the profile. */
    bool is_global;              /**< True if this is a global (read-only) profile; false if user-defined. */

    /* Settings */
    char *auto_switch_filter;    /**< Display filter expression that triggers automatic switching to this profile. */
} profile_def;

/**
 * @brief Initialize the profile list. Can be called more than once.
 * @param app_env_var_prefix The prefix for the application environment variable used to get the global configuration directory.
 */
void profile_init(const char* app_env_var_prefix);

/**
 * @brief Initialize the profile list. Can be called more than once.
 * @param app_env_var_prefix The prefix for the application environment variable used to get the global configuration directory.
 */
void profile_sync(const char* app_env_var_prefix);

/**
 * @brief Add a profile to the profile list
 * @param name Profile name
 * @param parent Parent profile name
 * @param is_global Profile is in the global configuration directory
 * @param auto_switch_filter Filter to use for auto switching profiles
 *
 * @return A pointer to the new profile list
 */
GList* profile_add_profile(const char *name, const char *parent, bool is_global, const char* auto_switch_filter);

/**
 * @brief Clear out the profile list
 */
void profile_empty_list(void);

/**
 * @brief Get the edited profile list
 * @return The head of the edited profile list
 */
GList* profile_get_list(void);

/**
 * @brief Determine if a string is a valid profile name
 * @param name Profile name to check
 * @return true if profile name is valid, false otherwise
 */
bool profile_name_is_valid(const char* name);

/** Maximum number of levels of nested profiles */
#define PROFILE_MAX_DEPTH 8

/**
 * @brief Get the sorted list of profile names in a profiles directory.
 * Nested profiles are named by their relative path using '/'.
 * @param directory The profiles directory
 * @return List of g_malloc()'d names, free with g_list_free_full(list, g_free)
 */
GList* profile_get_names(const char* directory);

/**
 * @brief Save the profile settings to disk
 * @param name Profile name
 * @param app_env_var_prefix The prefix for the application environment variable used to get the global configuration directory.
 * @param app_name Proper name of the application (used in file comment strings)
 * @param err_info Optional error info string.
 *
 * @return true if the profiles were successfully saved or false otherwise.
 */
bool profile_save_settings(const char* name, const char* app_env_var_prefix, const char* app_name, char** err_info);

/**
 * @brief Remove the current profile.
 *
 * @param app_env_var_prefix The prefix for the application environment variable used to get the global configuration directory.
 * @param err_info Optional error info string.
 *
 * @return true if the current profile exists and was successfully deleted
 * or false otherwise.
 */
bool profile_delete_current(const char* app_env_var_prefix, char** err_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PROFILE_H__ */
