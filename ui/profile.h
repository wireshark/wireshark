/* profile.h
 * Definitions for dialog box for profiles editing.
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
#define PROF_STAT_IMPORT   6

typedef struct {
    char     *name;             /* profile name */
    char     *reference;        /* profile reference */
    int       status;
    gboolean  is_global;
    gboolean  from_global;
    gboolean  is_import;
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
 * @param is_import Profile has been imported and no directory has to be created
 *
 * @return A pointer to the new profile list
 */
GList *add_to_profile_list(const char *name, const char *parent, int status,
                           gboolean is_global, gboolean from_global, gboolean is_import);

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
GList *current_profile_list(void);

/** Edited profile list
 *
 * @return The head of the edited profile list
 */
GList * edited_profile_list(void);

/** Apply the changes in the edited profile list
 * @return NULL if the operation was successful or an error message otherwise.
 * The error message must be freed by the caller.
 */
gchar *apply_profile_changes(void);

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
gchar *profile_name_is_valid(const gchar *name);

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
