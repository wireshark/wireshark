/** @file
 *
 * Inheritance of configuration file entries from parent profiles
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROFILE_INHERIT_H
#define PROFILE_INHERIT_H

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Name of the per-profile settings file. */
#define PROFILE_SETTINGS_FILENAME "profile_settings"

/** Prefix of the profile settings keys holding the inherit mode of a file. */
#define PROFILE_INHERIT_KEY_PREFIX "inherit."

/**
 * @brief Where the entries of a configuration file come from.
 *
 * Profiles are nested, and a top-level profile has the Default profile as
 * its parent. A global profile with the same name as a personal profile
 * comes right behind it, before the personal parent. Entries from the
 * profile itself always come first, and an entry from a parent which
 * duplicates an entry from a nearer profile is ignored.
 */
typedef enum {
    PROFILE_INHERIT_PROFILE_ONLY = 0,   /**< Entries from the profile only. */
    PROFILE_INHERIT_PROFILE_AND_PARENT, /**< Entries from the profile, then from the parent and up. */
    PROFILE_INHERIT_PARENT_ONLY         /**< Entries from the parent and up only. */
} profile_inherit_e;

/**
 * @brief A profile contributing entries to a configuration file.
 */
typedef struct {
    char *profile_name; /**< Name of the profile, "Default" for the Default profile. */
    char *profile_dir;  /**< Directory of the profile. */
    char *source;       /**< Shown as where an entry comes from: the profile name, with " (global)" for a global profile. */
    bool is_global;     /**< The profile is a global profile. */
    profile_inherit_e mode; /**< The inherit mode of this profile for the file; never PROFILE_INHERIT_PARENT_ONLY, and always PROFILE_INHERIT_PROFILE_ONLY for the Default profile. */
} profile_inherit_layer_t;

/**
 * @brief Convert an inherit mode to its profile settings string.
 *
 * @param mode The inherit mode.
 * @return A static string.
 */
WS_DLL_PUBLIC const char *profile_inherit_mode_to_str(profile_inherit_e mode);

/**
 * @brief Convert a profile settings string to an inherit mode.
 *
 * @param str The string, may be NULL.
 * @return The inherit mode, PROFILE_INHERIT_PROFILE_ONLY if not recognized.
 */
WS_DLL_PUBLIC profile_inherit_e profile_inherit_mode_from_str(const char *str);

/**
 * @brief Check whether a personal profile can inherit from a parent.
 *
 * The Default profile has no parent and cannot inherit.
 *
 * @param profile_name The profile name, NULL for the current profile.
 * @return true if the profile can inherit.
 */
WS_DLL_PUBLIC bool profile_can_inherit(const char *profile_name);

/**
 * @brief Get the name of the parent of a personal profile.
 *
 * @param profile_name The profile name, NULL for the current profile.
 * @return A g_malloc()'d name, "Default" for a top-level profile, or NULL for the Default profile.
 */
WS_DLL_PUBLIC char *profile_parent_name(const char *profile_name);

/**
 * @brief Get the first profile behind a personal profile, as shown to the user.
 *
 * This is the global profile with the same name if there is one, else the parent profile.
 *
 * @param app_env_var_prefix The prefix for the application environment variable.
 * @param profile_name The profile name, NULL for the current profile.
 * @return A g_malloc()'d name as in profile_inherit_layer_t.source, or NULL for the Default profile.
 */
WS_DLL_PUBLIC char *profile_inherit_parent_source(const char *app_env_var_prefix, const char *profile_name);

/**
 * @brief Get the inherit mode of a configuration file in a personal profile.
 *
 * @param app_env_var_prefix The prefix for the application environment variable.
 * @param profile_name The profile name, NULL for the current profile.
 * @param filename The configuration file name, e.g. "coloring_rules.jsonc".
 * @return The inherit mode, always PROFILE_INHERIT_PROFILE_ONLY for the Default profile.
 */
WS_DLL_PUBLIC profile_inherit_e profile_get_inherit(const char *app_env_var_prefix, const char *profile_name, const char *filename);

/**
 * @brief Set the inherit mode of a configuration file in a personal profile.
 *
 * Updates the profile settings file of the profile, keeping its other settings.
 *
 * @param app_env_var_prefix The prefix for the application environment variable.
 * @param profile_name The profile name, NULL for the current profile.
 * @param filename The configuration file name.
 * @param mode The inherit mode.
 * @param err_info Set to a g_malloc()'d error message on failure.
 * @return true on success.
 */
WS_DLL_PUBLIC bool profile_set_inherit(const char *app_env_var_prefix, const char *profile_name, const char *filename, profile_inherit_e mode, char **err_info);

/**
 * @brief The profile settings lines for the inherit mode of a configuration file.
 *
 * @param filename The configuration file name.
 * @param mode The inherit mode.
 * @return A g_malloc()'d string with a comment and the setting, each ending with a newline.
 */
WS_DLL_PUBLIC char *profile_inherit_settings_lines(const char *filename, profile_inherit_e mode);

/**
 * @brief Read the inherit settings from a profile settings file.
 *
 * @param path The path of the profile settings file.
 * @param err_info Set to a g_malloc()'d error message if the file exists but can't be read; may be NULL.
 * @return A hash table mapping file names to inherit mode strings, empty if
 * there is no file, or NULL if it can't be read. Free with g_hash_table_destroy().
 */
WS_DLL_PUBLIC GHashTable *profile_inherit_read_settings(const char *path, char **err_info);

/**
 * @brief Get the parent profiles contributing entries to a configuration file.
 *
 * The layers are ordered nearest parent first, where the global profile
 * with the same name as a personal profile, if any, comes right behind the
 * personal profile. Each parent uses its own
 * inherit mode for the file: a parent using the parent's entries only is
 * skipped, and the layers end with the first parent using its own entries
 * only, at the latest with the Default profile. A layer is included even
 * if its file does not exist; whether such a layer using its own entries
 * only falls back to global defaults is up to the caller.
 *
 * @param app_env_var_prefix The prefix for the application environment variable.
 * @param profile_name The profile name, NULL for the current profile.
 * @param filename The configuration file name.
 * @param mode The inherit mode of the profile itself, e.g. a mode not yet saved.
 * @return A GPtrArray of profile_inherit_layer_t, empty for PROFILE_INHERIT_PROFILE_ONLY.
 * Free with g_ptr_array_unref().
 */
WS_DLL_PUBLIC GPtrArray *profile_inherit_layers(const char *app_env_var_prefix, const char *profile_name, const char *filename, profile_inherit_e mode);

/**
 * @brief Keys of the entries read from the profiles nearer than the one being read.
 *
 * An entry is identified by one or two keys, e.g. a coloring rule by its
 * name and its filter, and is a duplicate if any of its keys was seen. The
 * keys of the profile being read are only added when it is done, so that
 * entries of the same profile don't hide each other.
 */
typedef struct profile_inherit_seen profile_inherit_seen_t;

/**
 * @brief Create an empty set of seen keys.
 * @return The set; free with profile_inherit_seen_free().
 */
WS_DLL_PUBLIC profile_inherit_seen_t *profile_inherit_seen_new(void);

/**
 * @brief Free a set of seen keys.
 * @param seen The set, may be NULL.
 */
WS_DLL_PUBLIC void profile_inherit_seen_free(profile_inherit_seen_t *seen);

/**
 * @brief Check whether an entry duplicates an entry from a nearer profile, and remember its keys.
 *
 * The keys are remembered for the profiles further up, once profile_inherit_seen_next() is called.
 * @param seen The set.
 * @param key1 The first key, e.g. the name of the entry.
 * @param key2 The second key, e.g. the filter of the entry, or NULL.
 * @return true if any key was seen in a nearer profile.
 */
WS_DLL_PUBLIC bool profile_inherit_seen_check(profile_inherit_seen_t *seen, const char *key1, const char *key2);

/**
 * @brief Done with the entries of a profile; its keys hide the same entries from the next profiles.
 * @param seen The set.
 */
WS_DLL_PUBLIC void profile_inherit_seen_next(profile_inherit_seen_t *seen);

/**
 * @brief Reads the entries of one parent profile.
 *
 * For each entry, call profile_inherit_seen_check() with its keys: an entry
 * duplicating one from a nearer profile, or disabled, is not inherited.
 *
 * @param layer The parent profile.
 * @param path The file to read.
 * @param filename Which of the file names was found, e.g. a legacy name.
 * @param seen The keys of the entries from the nearer profiles.
 * @param user_data The data passed to profile_inherit_read_layers().
 * @param err Set to a g_malloc()'d error message on failure.
 * @return true on success.
 */
typedef bool (*profile_inherit_read_layer_cb)(const profile_inherit_layer_t *layer, const char *path,
                                              const char *filename, profile_inherit_seen_t *seen,
                                              void *user_data, char **err);

/**
 * @brief Reads the entries inherited from the parent profiles of the current profile.
 *
 * Calls read for each parent profile contributing entries, nearest parent
 * first. A parent's file is filename, or else legacy_filename. Without one, a parent using its own entries only, like
 * the Default profile, reads the global filename if global_defaults is set,
 * as it would when it is the current profile; any other parent contributes
 * nothing. After each parent, its keys hide the same entries from the
 * parents further up.
 *
 * @param app_env_var_prefix The prefix for the application environment variable.
 * @param filename The configuration file name, which also names the inherit setting.
 * @param legacy_filename An older name of the file, or NULL.
 * @param global_defaults Whether a global filename holds defaults.
 * @param mode The inherit mode of the current profile, e.g. one not yet saved.
 * @param seen The keys of the profile's own entries.
 * @param read Reads the entries of one parent.
 * @param user_data Data passed to read.
 * @param err Set to a g_malloc()'d message for the first error, may be NULL.
 * @return true if all files were read.
 */
WS_DLL_PUBLIC bool profile_inherit_read_layers(const char *app_env_var_prefix, const char *filename,
                                               const char *legacy_filename, bool global_defaults,
                                               profile_inherit_e mode, profile_inherit_seen_t *seen,
                                               profile_inherit_read_layer_cb read, void *user_data, char **err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROFILE_INHERIT_H */
