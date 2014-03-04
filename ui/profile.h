/* profile.h
 * Definitions for dialog box for profiles editing.
 * Stig Bjorlykke <stig@bjorlykke.org>, 2008
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

#ifndef __PROFILE_H__
#define __PROFILE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * "Configuration Profiles" dialog box
 * @ingroup dialog_group
 */

#define PROF_STAT_DEFAULT  1
#define PROF_STAT_EXISTS   2
#define PROF_STAT_NEW      3
#define PROF_STAT_CHANGED  4
#define PROF_STAT_COPY     5

typedef struct {
  char *name;           /* profile name */
  char *reference;      /* profile reference */
  int   status;
  gboolean is_global;
  gboolean from_global;
} profile_def;

/** @file
 * "Configuration Profiles" utility routines
 * @ingroup utility_group
 */

/** Initialize the profile list. Can be called more than once.
 */
void init_profile_list(void);

/** User requested the "Configuration Profiles" popup menu.
 *
 * @param name Profile name
 * @param parent Parent profile name
 * @param status Current status
 * @param is_global Profile is in the global configuration directory
 * @param from_global Profile is copied from the global configuration directory
 *
 * @return A pointer to the new profile list
 */
GList * add_to_profile_list(const char *name, const char *parent, int status,
        gboolean is_global, gboolean from_global);

/** Refresh the current (non-edited) profile list.
 */
void copy_profile_list(void);

/** Clear out the profile list
 *
 * @param edit_list Remove edited entries
 */
void empty_profile_list(gboolean edit_list);

/** Remove an entry from the profile list.
 *
 * @param fl_entry Profile list entry
 */
void remove_from_profile_list(GList *fl_entry);

/** Current profile list
 *
 * @return The head of the current profile list
 */
GList * current_profile_list(void);

/** Edited profile list
 *
 * @return The head of the edited profile list
 */
GList * edited_profile_list(void);

/** Apply the changes in the edited profile list
 * @return NULL if the operation was successful or an error message otherwise.
 */
const gchar *apply_profile_changes(void);

/** Given a profile name, return the name of its parent profile.
 *
 * @param profilename Child profile name
 *
 * @return Parent profile name
 */
const gchar *get_profile_parent (const gchar *profilename);

/** Check the validity of a profile name.
 *
 * @param name Profile name
 * @return NULL if the name is valid or an error message otherwise.
 */
const gchar *profile_name_is_valid(const gchar *name);

/** Remove the current profile.
 *
 * @return TRUE if the current profile exists and was successfully deleted
 * or FALSE otherwise.
 */
gboolean delete_current_profile(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PROFILE_H__ */
