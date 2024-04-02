/* profile.c
 * Dialog box for profiles editing
 * Stig Bjorlykke <stig@bjorlykke.org>, 2008
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <errno.h>

#include <glib.h>

#include <epan/prefs.h>
#include <epan/prefs-int.h>

#include <wsutil/filesystem.h>

#include "profile.h"

#include "ui/simple_dialog.h"
#include "ui/recent.h"

#include <wsutil/file_util.h>
#include <wsutil/ws_assert.h>

static GList *current_profiles;
static GList *edited_profiles;

#define PROF_OPERATION_NEW  1
#define PROF_OPERATION_EDIT 2

GList * current_profile_list(void) {
    return g_list_first(current_profiles);
}

GList * edited_profile_list(void) {
    return g_list_first(edited_profiles);
}

static void load_profile_settings(profile_def *profile);
static void save_profile_settings(profile_def *profile);

static GList *
add_profile_entry(GList *fl, const char *profilename, const char *reference, int status,
        bool is_global, bool from_global, bool is_import)
{
    profile_def *profile;

    profile = g_new0(profile_def, 1);
    profile->name = g_strdup(profilename);
    profile->reference = g_strdup(reference);
    profile->status = status;
    profile->is_global = is_global;
    profile->from_global = from_global;
    profile->is_import = is_import;
    return g_list_append(fl, profile);
}

static GList *
remove_profile_entry(GList *fl, GList *fl_entry)
{
    GList *list;
    profile_def *profile;

    profile = (profile_def *) fl_entry->data;
    g_free(profile->name);
    g_free(profile->reference);
    g_free(profile->auto_switch_filter);
    g_free(profile);
    list = g_list_remove_link(fl, fl_entry);
    g_list_free_1(fl_entry);
    return list;
}

const char *
get_profile_parent (const char *profilename)
{
    GList *fl_entry = g_list_first(edited_profiles);
    unsigned no_edited = g_list_length(edited_profiles);
    profile_def *profile;
    unsigned i;

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

char *apply_profile_changes(void)
{
    char        *pf_dir_path, *pf_dir_path2, *pf_filename;
    GList       *fl1, *fl2;
    profile_def *profile1, *profile2;
    bool         found;
    char        *err_msg;

    /* First validate all profile names */
    fl1 = edited_profile_list();
    while (fl1) {
        profile1 = (profile_def *) fl1->data;
        g_strstrip(profile1->name);
        if ((err_msg = profile_name_is_valid(profile1->name)) != NULL) {
            char *message = ws_strdup_printf("%s\nProfiles unchanged.", err_msg);
            g_free(err_msg);
            return message;
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
                err_msg = ws_strdup_printf("Can't create directory\n\"%s\":\n%s.",
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
            if (strcmp(profile1->name, DEFAULT_PROFILE)!=0  && ! profile1->is_import) {
                if (create_persconffile_profile(profile1->name, &pf_dir_path) == -1) {
                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                            "Can't create directory\n\"%s\":\n%s.",
                            pf_dir_path, g_strerror(errno));

                    g_free(pf_dir_path);
                }
                profile1->status = PROF_STAT_EXISTS;

                g_free (profile1->reference);
                profile1->reference = g_strdup(profile1->name);
            /* correctly apply imports as existing profiles */
            } else if (profile1->is_import) {
                profile1->status = PROF_STAT_EXISTS;
                g_free (profile1->reference);
                profile1->reference = g_strdup(profile1->name);
                profile1->is_import = false;
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
            }
        }
        fl1 = g_list_next(fl1);
    }

    /* Last remove deleted */
    fl1 = current_profile_list();
    while (fl1) {
        found = false;
        profile1 = (profile_def *) fl1->data;
        fl2 = edited_profile_list();
        while (fl2) {
            profile2 = (profile_def *) fl2->data;
            if (!profile2->is_global) {
                if (strcmp(profile1->name, profile2->name)==0) {
                    /* Profile exists in both lists */
                    found = true;
                } else if (strcmp(profile1->name, profile2->reference)==0) {
                    /* Profile has been renamed, update reference to the new name */
                    g_free (profile2->reference);
                    profile2->reference = g_strdup(profile2->name);
                    found = true;
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

    /* Save our profile settings */
    for (fl1 = edited_profile_list() ; fl1 ; fl1 = fl1->next) {
        profile1 = (profile_def *) fl1->data;
        if (profile1->is_global) {
            continue;
        }
        if (profile1->prefs_changed) {
            save_profile_settings(profile1);
        }
    }

    copy_profile_list();
    return NULL;
}

GList *
add_to_profile_list(const char *name, const char *expression, int status,
        bool is_global, bool from_global, bool is_imported)
{
    edited_profiles = add_profile_entry(edited_profiles, name, expression, status,
            is_global, from_global, is_imported);

    return g_list_last(edited_profiles);
}

void
remove_from_profile_list(GList *fl_entry)
{
    edited_profiles = remove_profile_entry(edited_profiles, fl_entry);
}

void
empty_profile_list(bool edit_list)
{
    GList **flpp;

    if (edit_list) {
        flpp = &edited_profiles;

        while(*flpp) {
            *flpp = remove_profile_entry(*flpp, g_list_first(*flpp));
        }

        ws_assert(g_list_length(*flpp) == 0);
        if ( ! edited_profiles )
            edited_profiles = NULL;
    }

    flpp = &current_profiles;

    while(*flpp) {
        *flpp = remove_profile_entry(*flpp, g_list_first(*flpp));
    }

    ws_assert(g_list_length(*flpp) == 0);
    if ( ! current_profiles )
        current_profiles = NULL;
}

void
copy_profile_list(void)
{
    GList      *flp_src;
    profile_def *profile;

    flp_src = edited_profiles;

    /* throw away the "old" destination list - a NULL list is ok here */
    empty_profile_list(false);

    /* copy the list entries */
    while(flp_src) {
        profile = (profile_def *)(flp_src)->data;

        current_profiles = add_profile_entry(current_profiles, profile->name,
                profile->reference, profile->status,
                profile->is_global, profile->from_global, false);
        if (profile->auto_switch_filter) {
            profile_def *new_profile = (profile_def *) g_list_last(current_profiles)->data;
            new_profile->auto_switch_filter = g_strdup(profile->auto_switch_filter);
        }

        flp_src = g_list_next(flp_src);
    }
}

void
init_profile_list(void)
{
    WS_DIR        *dir;             /* scanned directory */
    WS_DIRENT     *file;            /* current file */
    const char    *name;
    GList         *local_profiles = NULL;
    GList         *global_profiles = NULL;
    GList         *iter, *item;
    char          *profiles_dir, *filename;

    empty_profile_list(true);

    /* Default entry */
    item = add_to_profile_list(DEFAULT_PROFILE, DEFAULT_PROFILE, PROF_STAT_DEFAULT, false, false, false);
    load_profile_settings((profile_def *)item->data);

    /* Local (user) profiles */
    profiles_dir = get_profiles_dir();
    if ((dir = ws_dir_open(profiles_dir, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            name = ws_dir_get_name(file);
            filename = ws_strdup_printf ("%s%s%s", profiles_dir, G_DIR_SEPARATOR_S, name);

            if (test_for_directory(filename) == EISDIR) {
                local_profiles = g_list_prepend(local_profiles, g_strdup(name));
            }
            g_free (filename);
        }
        ws_dir_close (dir);
    }
    g_free(profiles_dir);

    local_profiles = g_list_sort(local_profiles, (GCompareFunc)g_ascii_strcasecmp);
    for (iter = g_list_first(local_profiles); iter; iter = g_list_next(iter)) {
        name = (char *)iter->data;
        item = add_to_profile_list(name, name, PROF_STAT_EXISTS, false, false, false);
        load_profile_settings((profile_def *)item->data);
    }
    g_list_free_full(local_profiles, g_free);

    /* Global profiles */
    profiles_dir = get_global_profiles_dir();
    if ((dir = ws_dir_open(profiles_dir, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            name = ws_dir_get_name(file);
            filename = ws_strdup_printf ("%s%s%s", profiles_dir, G_DIR_SEPARATOR_S, name);

            if (test_for_directory(filename) == EISDIR) {
                global_profiles = g_list_prepend(global_profiles, g_strdup(name));
            }
            g_free (filename);
        }
        ws_dir_close (dir);
    }
    g_free(profiles_dir);

    global_profiles = g_list_sort(global_profiles, (GCompareFunc)g_ascii_strcasecmp);
    for (iter = g_list_first(global_profiles); iter; iter = g_list_next(iter)) {
        name = (char *)iter->data;
        add_to_profile_list(name, name, PROF_STAT_EXISTS, true, true, false);
    }
    g_list_free_full(global_profiles, g_free);

    /* Make the current list and the edited list equal */
    copy_profile_list ();
}

char *
profile_name_is_valid(const char *name)
{
    char *reason = NULL;
    char *message;

#ifdef _WIN32
    char *invalid_dir_char = "\\/:*?\"<>|";
    bool invalid = false;
    int i;

    for (i = 0; i < 9; i++) {
        if (strchr(name, invalid_dir_char[i])) {
            /* Invalid character in directory */
            invalid = true;
        }
    }
    if (name[0] == '.' || name[strlen(name)-1] == '.') {
        /* Profile name cannot start or end with period */
        invalid = true;
    }
    if (invalid) {
        reason = ws_strdup_printf("start or end with period (.), or contain any of the following characters:\n"
                "   \\ / : * ? \" &lt; &gt; |");
    }
#else
    if (strchr(name, '/')) {
        /* Invalid character in directory */
        reason = ws_strdup_printf("contain the '/' character.");
    }
#endif

    if (reason) {
        message = ws_strdup_printf("A profile name cannot %s", reason);
        g_free(reason);
        return message;
    }

    return NULL;
}

bool delete_current_profile(void) {
    const char *name = get_profile_name();
    char        *pf_dir_path;

    if (profile_exists(name, false) && strcmp (name, DEFAULT_PROFILE) != 0) {
        if (delete_persconffile_profile(name, &pf_dir_path) == -1) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Can't delete profile directory\n\"%s\":\n%s.",
                    pf_dir_path, g_strerror(errno));

            g_free(pf_dir_path);
        } else {
            return true;
        }
    }
    return false;
}

// Use a settings file in case we ever want to include an author, description,
// URL, etc.
#define PROFILE_SETTINGS_FILENAME "profile_settings"
#define AUTO_SWITCH_FILTER_KEY "auto_switch_filter"

static char *get_profile_settings_path(const char *profile_name) {
    char *profile_settings_path;
    char *profile_dir = get_profile_dir(profile_name, false);
    profile_settings_path = g_build_filename(profile_dir, PROFILE_SETTINGS_FILENAME, NULL);
    g_free(profile_dir);

    return profile_settings_path;
}

/* Set  */
static prefs_set_pref_e
set_profile_setting(char *key, const char *value, void *profile_ptr, bool return_range_errors _U_)
{
    profile_def *profile = (profile_def *) profile_ptr;
    if (strcmp(key, AUTO_SWITCH_FILTER_KEY) == 0) {
        g_free(profile->auto_switch_filter);
        profile->auto_switch_filter = g_strdup(value);
    }

    return PREFS_SET_OK;
}

static void load_profile_settings(profile_def *profile)
{
    char *profile_settings_path = get_profile_settings_path(profile->name);
    FILE *fp;

    if ((fp = ws_fopen(profile_settings_path, "r")) != NULL) {
        read_prefs_file(profile_settings_path, fp, set_profile_setting, profile);
        fclose(fp);
    }
    g_free(profile_settings_path);
}

void save_profile_settings(profile_def *profile)
{
    char *profile_settings_path = get_profile_settings_path(profile->name);
    FILE *fp;

    if ((fp = ws_fopen(profile_settings_path, "w")) == NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Can't open recent file\n\"%s\": %s.", profile_settings_path,
                      g_strerror(errno));
        g_free(profile_settings_path);
        return;
    }
    g_free(profile_settings_path);

    fprintf(fp, "# \"%s\" profile settings file for %s " VERSION ". Edit with care.\n",
            profile->name, get_configuration_namespace());

    fprintf(fp, "\n# Automatically switch to this profile if this display filter matches.\n");
    fprintf(fp, AUTO_SWITCH_FILTER_KEY ": %s\n", profile->auto_switch_filter);

    fclose(fp);
}
