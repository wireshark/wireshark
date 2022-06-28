/** @file
 *
 * Routines for handling preferences
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PREFRENCE_UTILS_H__
#define __PREFRENCE_UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Preference utility routines.
 *  @ingroup prefs_group
 */

/** If autoscroll in live captures is active or not
 */
extern gboolean auto_scroll_live;

/** Fill in capture options with values from the preferences
 */
extern void prefs_to_capture_opts(void);

/** Save all preferences
 */
extern void prefs_main_write(void);

/** Convenient function for plugin_if
 *
 * Note: The preferences must exist, it is not possible to create entries
 * using this function
 *
 * @param module the module for the preference
 * @param key the key for the preference
 * @param value the new value as string for the preference
 *
 * @return flags of types of preferences changed, non-zero if the value has been stored successfully
 */
extern unsigned int prefs_store_ext(const char * module, const char * key, const char * value);

/** Convenient function for the writing of multiple preferences, without
 * explicitly having prefs_t variables.
 *
 * Note: The preferences must exist, it is not possible to create entries
 * using this function
 *
 * @param module the module for the preference
 * @param pref_values a hash table
 *
 * @return true if the value has been stored successfully
 */
extern gboolean prefs_store_ext_multiple(const char * module, GHashTable * pref_values);

/** Add a custom column.
 *
 * @param fmt column format
 * @param title column title
 * @param custom_field column custom field
 * @param position the intended position of the insert
 *
 * @return The index of the inserted column
 */
gint column_prefs_add_custom(gint fmt, const gchar *title,
                             const gchar *custom_field,
                             gint position);

/** Check if a custom column exists.
 *
 * @param custom_field column custom field
 *
 * @return The index of the column if existing, -1 if not existing
 */
gint column_prefs_has_custom(const gchar *custom_field);

/** Check if a custom column's data can be displayed differently
 * resolved or unresolved, e.g. it has a field with a value string.
 *
 * This is for when adding or editing custom columns. Compare with
 * resolve_column() in packet_list_utils.h, which is for columns
 * that have already been added.
 *
 * @param custom_field column custom field
 *
 * @return TRUE if a custom column with the field description
 * would support being displayed differently resolved or unresolved,
 * FALSE otherwise.
 */
gboolean column_prefs_custom_resolve(const gchar *custom_field);

/** Remove a column.
 *
 * @param col_link Column list entry
 */
void column_prefs_remove_link(GList* col_link);

/** Remove a column.
 *
 * @param col Column number
 */
void column_prefs_remove_nth(gint col);

/** Save the UAT and complete migration of old preferences by writing the main
 * preferences file (if necessary).
 */
void save_migrated_uat(const char *uat_name, gboolean *old_pref);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PREFRENCE_UTILS_H__ */
