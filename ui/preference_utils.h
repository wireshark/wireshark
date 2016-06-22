/* preference_utils.h
 * Routines for handling preferences
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

/** "Stash" a preference.
 * Copy a preference to its stashed value. Can be called from prefs_pref_foreach().
 *
 * @param pref A preference.
 * @param unused unused
 */
extern guint pref_stash(pref_t *pref, gpointer unused _U_);

/** "Untash" a preference.
 * Set a preference to its stashed value. Can be called from prefs_pref_foreach().
 *
 * @param pref A preference.
 * @param changed_p A pointer to a gboolean. Set to TRUE if the preference differs
 * from its stashed value.
 *
 * @return Always returns 0.
 */
extern guint pref_unstash(pref_t *pref, gpointer changed_p);

/** Clean up a stashed preference.
 * Can be called from prefs_pref_foreach().
 *
 * @param pref A preference.
 * @param unused unused
 *
 * @return Always returns 0.
 */
extern guint pref_clean_stash(pref_t *pref, gpointer unused _U_);

/** Set a stashed preference to its default value.
 *
 *@param pref A preference.
 */
extern void reset_stashed_pref(pref_t *pref);


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
 * @return true if the value has been stored successfully
 */
extern gboolean prefs_store_ext(const char * module, const char * key, const char * value);

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
 * @param custom_occurrence custom occurrence
 *
 * @return The index of the inserted column
 */
gint column_prefs_add_custom(gint fmt, const gchar *title,
                             const gchar *custom_field,
                             gint custom_occurrence);

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


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PREFRENCE_UTILS_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
