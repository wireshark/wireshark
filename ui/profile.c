/* profile.c
 * Storage of profile information
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
#include <wsutil/file_util.h>

#include "profile.h"


static GList *edited_profiles;

GList * profile_get_list(void) {
    return g_list_first(edited_profiles);
}

static void load_profile_settings(profile_def *profile, const char* app_env_var_prefix);

static GList *
add_profile_entry(GList *fl, const char *profilename, const char *reference,
        bool is_global, const char* auto_switch_filter)
{
    profile_def *profile;

    profile = g_new0(profile_def, 1);
    profile->name = g_strdup(profilename);
    profile->reference = g_strdup(reference);
    profile->auto_switch_filter = g_strdup(auto_switch_filter ? auto_switch_filter : "");
    profile->is_global = is_global;
    return g_list_append(fl, profile);
}

GList*
profile_add_profile(const char* name, const char* expression, bool is_global, const char* auto_switch_filter)
{
    edited_profiles = add_profile_entry(edited_profiles, name, expression, is_global, auto_switch_filter);

    return g_list_last(edited_profiles);
}

static void
remove_profile_entry(profile_def* profile)
{
    g_free(profile->name);
    g_free(profile->reference);
    g_free(profile->auto_switch_filter);
    g_free(profile);
}

static profile_def* profile_find_by_name(const char* name, bool is_global)
{
    GList *iter;
    for (iter = g_list_first(edited_profiles); iter; iter = g_list_next(iter)) {
        profile_def* profile = (profile_def*)iter->data;
        if (strcmp(profile->name, name) == 0 && profile->is_global == is_global) {
            return profile;
        }
    }
    return NULL;
}

bool
profile_name_is_valid(const char* name)
{
    bool valid = true;

#ifdef _WIN32
    if (strpbrk(name, WS_FILENAME_RESERVED_PRINTABLE_CHARS)) {
        /* Invalid character in directory */
        valid = false;
    }
    if (name[0] == '.' || name[strlen(name) - 1] == '.') {
        /* Profile name cannot start or end with period */
        valid = false;
    }
#else
    if (strchr(name, '/')) {
        /* Invalid character in directory */
        valid = false;
    }
#endif

    return valid;
}

/* Get (sorted) list of profiles in a directory */
static GList*
get_profiles(const char* directory)
{
    WS_DIR        *dir;             /* scanned directory */
    WS_DIRENT     *file;            /* current file */
    const char    *name;
    GList         *profiles = NULL;
    char          *filename;

    if ((dir = ws_dir_open(directory, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            name = ws_dir_get_name(file);
            if (!profile_name_is_valid(name))   //Skip directories that are not valid profile names
                continue;

            filename = ws_strdup_printf ("%s%s%s", directory, G_DIR_SEPARATOR_S, name);

            if (test_for_directory(filename) == EISDIR)
                profiles = g_list_prepend(profiles, g_strdup(name));

            g_free(filename);
        }
        ws_dir_close(dir);
    }

    profiles = g_list_sort(profiles, (GCompareFunc)g_ascii_strcasecmp);

    return profiles;
}

void
profile_init(const char* app_env_var_prefix)
{
    const char    *name;
    GList         *local_profiles = NULL;
    GList         *global_profiles = NULL;
    GList         *iter, *item;
    char          *profiles_dir;

    /* Default entry */
    item = profile_add_profile(DEFAULT_PROFILE, DEFAULT_PROFILE, false, "");
    load_profile_settings((profile_def *)item->data, app_env_var_prefix);

    /* Local (user) profiles */
    profiles_dir = get_profiles_dir(app_env_var_prefix);
    local_profiles = get_profiles(profiles_dir);
    g_free(profiles_dir);

    for (iter = g_list_first(local_profiles); iter; iter = g_list_next(iter)) {
        name = (char *)iter->data;
        item = profile_add_profile(name, name, false, "");
        load_profile_settings((profile_def *)item->data, app_env_var_prefix);
    }
    g_list_free_full(local_profiles, g_free);

    /* Global profiles */
    profiles_dir = get_global_profiles_dir(app_env_var_prefix);
    global_profiles = get_profiles(profiles_dir);
    g_free(profiles_dir);

    for (iter = g_list_first(global_profiles); iter; iter = g_list_next(iter)) {
        name = (char *)iter->data;
        item = profile_add_profile(name, name, true, "");
        load_profile_settings((profile_def *)item->data, app_env_var_prefix);
    }
    g_list_free_full(global_profiles, g_free);
}

void profile_sync(const char* app_env_var_prefix)
{
    const char* name;
    char* profiles_dir;
    GList *local_profiles = NULL, *global_profiles = NULL;
    GList *iter, *lp_iter, *gp_iter;

    /* Local (user) profiles */
    profiles_dir = get_profiles_dir(app_env_var_prefix);
    local_profiles = get_profiles(profiles_dir);
    g_free(profiles_dir);

    /* Global profiles */
    profiles_dir = get_global_profiles_dir(app_env_var_prefix);
    global_profiles = get_profiles(profiles_dir);
    g_free(profiles_dir);

    /*
     * Look for profiles that no longer have a directory and remove them
     */
    iter = g_list_first(edited_profiles);
    /* Always skip the default profile (first) */
    iter = g_list_next(iter);

    while (iter) {
        profile_def* profile = (profile_def*)iter->data;
        bool found = false;
        for (lp_iter = g_list_first(local_profiles); lp_iter; lp_iter = g_list_next(lp_iter)) {
            name = (char*)lp_iter->data;
            if (strcmp(profile->name, name) == 0 && !profile->is_global) {
                found = true;
                break;
            }
        }
        if (!found) {
            for (gp_iter = g_list_first(global_profiles); gp_iter; gp_iter = g_list_next(gp_iter)) {
                name = (char*)gp_iter->data;
                if (strcmp(profile->name, name) == 0 && profile->is_global) {
                    found = true;
                    break;
                }
            }
        }
        GList* next = g_list_next(iter);
        if (!found) {
            edited_profiles = g_list_remove(edited_profiles, profile);
            remove_profile_entry(profile);
        }
        iter = next;
    }
    /*
     * Now add profiles that are new
     */
    for (lp_iter = g_list_first(local_profiles); lp_iter; lp_iter = g_list_next(lp_iter)) {
        name = (char*)lp_iter->data;
        if (profile_find_by_name(name, false) == NULL) {
            GList* item = profile_add_profile(name, name, false, "");
            load_profile_settings((profile_def *)item->data, app_env_var_prefix);
        }
    }
    for (gp_iter = g_list_first(global_profiles); gp_iter; gp_iter = g_list_next(gp_iter)) {
        name = (char*)gp_iter->data;
        if (profile_find_by_name(name, true) == NULL) {
            GList* item = profile_add_profile(name, name, true, "");
            load_profile_settings((profile_def*)item->data, app_env_var_prefix);
        }
    }

    /* Clean up */
    g_list_free_full(local_profiles, g_free);
    g_list_free_full(global_profiles, g_free);

}

bool profile_delete_current(const char* app_env_var_prefix, char** err_info) {
    const char *name = get_profile_name();
    char        *pf_dir_path;

    if (profile_exists(app_env_var_prefix, name, false) && strcmp (name, DEFAULT_PROFILE) != 0) {
        if (delete_persconffile_profile(app_env_var_prefix, name, &pf_dir_path) == -1) {
            *err_info = g_strdup_printf("Can't delete profile directory\n\"%s\":\n%s.",
                    pf_dir_path, g_strerror(errno));

            g_free(pf_dir_path);
        } else {

            //Remove the profile from the list
            GList* item = edited_profiles;
            while (item != NULL) {
                profile_def* profile = (profile_def*)item->data;
                if (strcmp(profile->name, name) == 0) {
                    edited_profiles = g_list_remove(edited_profiles, profile);
                    remove_profile_entry(profile);
                    break;
                }
                item = g_list_next(item);
            }
            return true;
        }
    }
    return false;
}

void profile_empty_list(void)
{
    GList** flpp = &edited_profiles;

    while (*flpp) {
        GList* first = g_list_first(*flpp);
        profile_def* profile = first->data;
        remove_profile_entry(profile);
        *flpp = g_list_remove_link(*flpp, first);
        g_list_free_1(first);
    }

    edited_profiles = NULL;
}

// Use a settings file in case we ever want to include an author, description,
// URL, etc.
#define PROFILE_SETTINGS_FILENAME "profile_settings"
#define AUTO_SWITCH_FILTER_KEY "auto_switch_filter"

static char *get_profile_settings_path(const char *profile_name, bool is_global, const char* app_env_var_prefix) {
    char *profile_settings_path;
    char *profile_dir = get_profile_dir(app_env_var_prefix, profile_name, is_global);
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

static void load_profile_settings(profile_def *profile, const char* app_env_var_prefix)
{
    char *profile_settings_path = get_profile_settings_path(profile->name, profile->is_global, app_env_var_prefix);
    FILE *fp;

    if ((fp = ws_fopen(profile_settings_path, "r")) != NULL) {
        read_prefs_file(profile_settings_path, fp, set_profile_setting, profile);
        fclose(fp);
    }
    g_free(profile_settings_path);
}

bool profile_save_settings(const char* name, const char* app_env_var_prefix, const char* app_name, char** err_info)
{
    profile_def* profile = NULL;

    GList *fl1 = profile_get_list();
    while (fl1) {
        if (strcmp(((profile_def*)fl1->data)->name, name) == 0) {
            profile = (profile_def*)fl1->data;
            break;
        }
        fl1 = g_list_next(fl1);
    }

    //Didn't find the profile
    if (profile == NULL) {
        *err_info = g_strdup_printf("Can't find profile %s\n.", name);
        return false;
    }

    char *profile_settings_path = get_profile_settings_path(profile->name, false, app_env_var_prefix);
    FILE *fp;


    if ((fp = ws_fopen(profile_settings_path, "w")) == NULL) {
        *err_info = g_strdup_printf("Can't open recent file\n\"%s\": %s.", profile_settings_path,
            g_strerror(errno));
        g_free(profile_settings_path);
        return false;
    }
    g_free(profile_settings_path);

    fprintf(fp, "# \"%s\" profile settings file for %s " VERSION ". Edit with care.\n",
            profile->name, app_name);

    fprintf(fp, "\n# Automatically switch to this profile if this display filter matches.\n");
    fprintf(fp, AUTO_SWITCH_FILTER_KEY ": %s\n", profile->auto_switch_filter);

    fclose(fp);
    return true;
}
