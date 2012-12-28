/* profile.c
 * Dialog box for profiles editing
 * Stig Bjorlykke <stig@bjorlykke.org>, 2008
 *
 * $Id$
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

#include <epan/filesystem.h>
#include <epan/prefs.h>

#include "ui/recent.h"

#include <wsutil/file_util.h>

static GList *current_profiles = NULL;
static GList *edited_profiles = NULL;

#define PROF_STAT_DEFAULT  1
#define PROF_STAT_EXISTS   2
#define PROF_STAT_NEW      3
#define PROF_STAT_CHANGED  4
#define PROF_STAT_COPY     5

#define PROF_OPERATION_NEW  1
#define PROF_OPERATION_EDIT 2

typedef struct {
    char *name;           /* profile name */
    char *reference;      /* profile reference */
    int   status;
    gboolean is_global;
    gboolean from_global;
} profile_def;

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

    profile = (profile_def *) g_malloc(sizeof(profile_def));
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
        profile = (flp_src)->data;

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
    /*GList         *fl_entry;*/
    /*profile_def   *profile;*/
    const gchar   *profiles_dir, *name;
    gchar         *filename;

    empty_profile_list(TRUE);

    /* Default entry */
    /*fl_entry =*/ add_to_profile_list(DEFAULT_PROFILE, DEFAULT_PROFILE, PROF_STAT_DEFAULT, FALSE, FALSE);

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

const gchar *
profile_name_is_valid(const gchar *name)
{
    gchar *reason = NULL;
    emem_strbuf_t  *message = ep_strbuf_new(NULL);

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
        ep_strbuf_printf(message, "A profile name cannot %s\nProfiles unchanged.", reason);
        g_free(reason);
        return message->str;
    }

    return NULL;
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
