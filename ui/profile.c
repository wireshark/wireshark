/* profile.c
 * Dialog box for profiles editing
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

#include "config.h"

#include <string.h>
#include <errno.h>

#include <glib.h>

#include <wsutil/filesystem.h>

#include "profile.h"

#include "ui/simple_dialog.h"
#include "ui/recent.h"

#include <wsutil/file_util.h>

static GList *current_profiles = NULL;
static GList *edited_profiles = NULL;

#define PROF_OPERATION_NEW  1
#define PROF_OPERATION_EDIT 2

GList * current_profile_list(void) {
    return g_list_first(current_profiles);
}

GList * edited_profile_list(void) {
    return g_list_first(edited_profiles);
}

static GList *
add_profile_entry(GList *fl, const char *profilename, const char *reference, int status,
        gboolean is_global, gboolean from_global)
{
    profile_def *profile;

    profile = (profile_def *) g_malloc0(sizeof(profile_def));
    profile->name = g_strdup(profilename);
    profile->reference = g_strdup(reference);
    profile->status = status;
    profile->is_global = is_global;
    profile->from_global = from_global;
    return g_list_append(fl, profile);
}

static GList *
remove_profile_entry(GList *fl, GList *fl_entry)
{
    profile_def *profile;

    profile = (profile_def *) fl_entry->data;
    g_free(profile->name);
    g_free(profile->reference);
    g_free(profile);
    return g_list_remove_link(fl, fl_entry);
}

const gchar *
get_profile_parent (const gchar *profilename)
{
    GList *fl_entry = g_list_first(edited_profiles);
    guint no_edited = g_list_length(edited_profiles);
    profile_def *profile;
    guint i;

    if (fl_entry) {
        /* We have edited profiles, find parent */
        for (i = 0; i < no_edited; i++) {
            while (fl_entry) {
                profile = (profile_def *) fl_entry->data;
                if (strcmp (profile->name, profilename) == 0) {
                    if ((profile->status == PROF_STAT_NEW) ||
                            (profile->reference == NULL)) {
                        /* Copy from a new profile */
                        return NULL;
                    } else {
                        /* Found a parent, use this */
                        profilename = profile->reference;
                    }
                }
                fl_entry = g_list_next(fl_entry);
            }
            fl_entry = g_list_first(edited_profiles);
        }
    }

    return profilename;
}

const gchar *apply_profile_changes(void)
{
    char        *pf_dir_path, *pf_dir_path2, *pf_filename;
    GList       *fl1, *fl2;
    profile_def *profile1, *profile2;
    gboolean     found;
    const gchar *err_msg;

    /* First validate all profile names */
    fl1 = edited_profile_list();
    while (fl1) {
        profile1 = (profile_def *) fl1->data;
        g_strstrip(profile1->name);
        if ((err_msg = profile_name_is_valid(profile1->name)) != NULL) {
            return err_msg;
        }
        fl1 = g_list_next(fl1);
    }

    /* Write recent file for current profile before copying or renaming */
    write_profile_recent();

    /* Then do all copy profiles */
    fl1 = edited_profile_list();
    while (fl1) {
        profile1 = (profile_def *) fl1->data;
        g_strstrip(profile1->name);
        if (profile1->status == PROF_STAT_COPY) {
            if (create_persconffile_profile(profile1->name, &pf_dir_path) == -1) {
                err_msg = g_strdup_printf("Can't create directory\n\"%s\":\n%s.",
                        pf_dir_path, g_strerror(errno));

                g_free(pf_dir_path);
                return err_msg;
            }
            profile1->status = PROF_STAT_EXISTS;

            if (profile1->reference) {
                if (copy_persconffile_profile(profile1->name, profile1->reference, profile1->from_global,
                            &pf_filename, &pf_dir_path, &pf_dir_path2) == -1) {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                            "Can't copy file \"%s\" in directory\n\"%s\" to\n\"%s\":\n%s.",
                            pf_filename, pf_dir_path2, pf_dir_path, g_strerror(errno));

                    g_free(pf_filename);
                    g_free(pf_dir_path);
                    g_free(pf_dir_path2);
                }
            }

            g_free (profile1->reference);
            profile1->reference = g_strdup(profile1->name);
        }
        fl1 = g_list_next(fl1);
    }


    /* Then create new and rename changed */
    fl1 = edited_profile_list();
    while (fl1) {
        profile1 = (profile_def *) fl1->data;
        g_strstrip(profile1->name);
        if (profile1->status == PROF_STAT_NEW) {
            /* We do not create a directory for the default profile */
            if (strcmp(profile1->name, DEFAULT_PROFILE)!=0) {
                if (create_persconffile_profile(profile1->name, &pf_dir_path) == -1) {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                            "Can't create directory\n\"%s\":\n%s.",
                            pf_dir_path, g_strerror(errno));

                    g_free(pf_dir_path);
                }
                profile1->status = PROF_STAT_EXISTS;

                g_free (profile1->reference);
                profile1->reference = g_strdup(profile1->name);
            }
        } else if (profile1->status == PROF_STAT_CHANGED) {
            if (strcmp(profile1->reference, profile1->name)!=0) {
                /* Rename old profile directory to new */
                if (rename_persconffile_profile(profile1->reference, profile1->name,
                            &pf_dir_path, &pf_dir_path2) == -1) {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                            "Can't rename directory\n\"%s\" to\n\"%s\":\n%s.",
                            pf_dir_path, pf_dir_path2, g_strerror(errno));

                    g_free(pf_dir_path);
                    g_free(pf_dir_path2);
                }
                profile1->status = PROF_STAT_EXISTS;
                g_free (profile1->reference);
                profile1->reference = g_strdup(profile1->name);
            }
        }
        fl1 = g_list_next(fl1);
    }

    /* Last remove deleted */
    fl1 = current_profile_list();
    while (fl1) {
        found = FALSE;
        profile1 = (profile_def *) fl1->data;
        fl2 = edited_profile_list();
        while (fl2) {
            profile2 = (profile_def *) fl2->data;
            if (!profile2->is_global) {
                if (strcmp(profile1->name, profile2->name)==0) {
                    /* Profile exists in both lists */
                    found = TRUE;
                } else if (strcmp(profile1->name, profile2->reference)==0) {
                    /* Profile has been renamed */
                    found = TRUE;
                }
            }
            fl2 = g_list_next(fl2);
        }
        if (!found) {
            /* Exists in existing list and not in edited, this is a deleted profile */
            if (delete_persconffile_profile(profile1->name, &pf_dir_path) == -1) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                        "Can't delete profile directory\n\"%s\":\n%s.",
                        pf_dir_path, g_strerror(errno));

                g_free(pf_dir_path);
            }
        }
        fl1 = g_list_next(fl1);
    }

    copy_profile_list();
    return NULL;
}

GList *
add_to_profile_list(const char *name, const char *expression, int status,
        gboolean is_global, gboolean from_global)
{
    edited_profiles = add_profile_entry(edited_profiles, name, expression, status,
            is_global, from_global);

    return g_list_last(edited_profiles);
}

void
remove_from_profile_list(GList *fl_entry)
{
    edited_profiles = remove_profile_entry(edited_profiles, fl_entry);
}

void
empty_profile_list(gboolean edit_list)
{
    GList **flpp;

    if (edit_list) {
        flpp = &edited_profiles;

        while(*flpp) {
            *flpp = remove_profile_entry(*flpp, g_list_first(*flpp));
        }

        g_assert(g_list_length(*flpp) == 0);
    }

    flpp = &current_profiles;

    while(*flpp) {
        *flpp = remove_profile_entry(*flpp, g_list_first(*flpp));
    }

    g_assert(g_list_length(*flpp) == 0);
}

void
copy_profile_list(void)
{
    GList      *flp_src;
    profile_def *profile;

    flp_src = edited_profiles;

    /* throw away the "old" destination list - a NULL list is ok here */
    empty_profile_list(FALSE);

    /* copy the list entries */
    while(flp_src) {
        profile = (profile_def *)(flp_src)->data;

        current_profiles = add_profile_entry(current_profiles, profile->name,
                profile->reference, profile->status,
                profile->is_global, profile->from_global);
        flp_src = g_list_next(flp_src);
    }
}

void
init_profile_list(void)
{
    WS_DIR        *dir;             /* scanned directory */
    WS_DIRENT     *file;            /* current file */
    const gchar   *profiles_dir, *name;
    gchar         *filename;

    empty_profile_list(TRUE);

    /* Default entry */
    add_to_profile_list(DEFAULT_PROFILE, DEFAULT_PROFILE, PROF_STAT_DEFAULT, FALSE, FALSE);

    /* Local (user) profiles */
    profiles_dir = get_profiles_dir();
    if ((dir = ws_dir_open(profiles_dir, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            name = ws_dir_get_name(file);
            filename = g_strdup_printf ("%s%s%s", profiles_dir, G_DIR_SEPARATOR_S, name);

            if (test_for_directory(filename) == EISDIR) {
                /*fl_entry =*/ add_to_profile_list(name, name, PROF_STAT_EXISTS, FALSE, FALSE);
            }
            g_free (filename);
        }
        ws_dir_close (dir);
    }

    /* Global profiles */
    profiles_dir = get_global_profiles_dir();
    if ((dir = ws_dir_open(profiles_dir, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            name = ws_dir_get_name(file);
            filename = g_strdup_printf ("%s%s%s", profiles_dir, G_DIR_SEPARATOR_S, name);

            if (test_for_directory(filename) == EISDIR) {
                /*fl_entry =*/ add_to_profile_list(name, name, PROF_STAT_EXISTS, TRUE, TRUE);
                /*profile = (profile_def *) fl_entry->data;*/
            }
            g_free (filename);
        }
        ws_dir_close (dir);
    }

    /* Make the current list and the edited list equal */
    copy_profile_list ();
}

gchar *
profile_name_is_valid(const gchar *name)
{
    gchar *reason = NULL;
    gchar *message;

#ifdef _WIN32
    char *invalid_dir_char = "\\/:*?\"<>|";
    gboolean invalid = FALSE;
    int i;

    for (i = 0; i < 9; i++) {
        if (strchr(name, invalid_dir_char[i])) {
            /* Invalid character in directory */
            invalid = TRUE;
        }
    }
    if (name[0] == '.' || name[strlen(name)-1] == '.') {
        /* Profile name cannot start or end with period */
        invalid = TRUE;
    }
    if (invalid) {
        reason = g_strdup_printf("start or end with period (.), or contain any of the following characters:\n"
                "   \\ / : * ? \" &lt; &gt; |");
    }
#else
    if (strchr(name, '/')) {
        /* Invalid character in directory */
        reason = g_strdup_printf("contain the '/' character.");
    }
#endif

    if (reason) {
        message = g_strdup_printf("A profile name cannot %s\nProfiles unchanged.", reason);
        g_free(reason);
        return message;
    }

    return NULL;
}

gboolean delete_current_profile(void) {
    const gchar *name = get_profile_name();
    char        *pf_dir_path;

    if (profile_exists(name, FALSE) && strcmp (name, DEFAULT_PROFILE) != 0) {
        if (delete_persconffile_profile(name, &pf_dir_path) == -1) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Can't delete profile directory\n\"%s\":\n%s.",
                    pf_dir_path, g_strerror(errno));

            g_free(pf_dir_path);
        } else {
            return TRUE;
        }
    }
    return FALSE;
}

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
