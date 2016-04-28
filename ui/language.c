/* language.c
 * Language "preference" handling routines
 * Copyright 2014, Michal Labedzki for Tieto Corporation
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

#include <stdlib.h>
#include <errno.h>

#include <epan/prefs.h>
#include <epan/prefs-int.h>

#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>

#include "ui/language.h"
#include "ui/simple_dialog.h"

#define LANGUAGE_FILE_NAME      "language"
#define LANGUAGE_PREF_LANGUAGE  "language"

char *language = NULL;

/* set one user's recent common file key/value pair */
static prefs_set_pref_e
read_language_pref(gchar *key, const gchar *value,
                   void *private_data _U_, gboolean return_range_errors _U_)
{
    if (strcmp(key, LANGUAGE_PREF_LANGUAGE) == 0) {
        if (language)
            g_free(language);
        /*
         * For backwards compatibility, treat "auto" as meaning "use the
         * system language".
         *
         * To handle the old buggy code that didn't check whether "language"
         * was null before trying to print it, treat "(null)" - which many,
         * but *NOT* all, system printfs print for a null pointer (some
         * printfs, such as the one in Solaris, *crash* with %s and a null
         * pointer) - as meaning "use the system language".
         */
        if (!value || !*value || strcmp(value, "auto") == 0 ||
            strcmp(value, "(null)") == 0)
            language = g_strdup(USE_SYSTEM_LANGUAGE);
        else
            language = g_strdup(value);
    }

    return PREFS_SET_OK;
}

void
read_language_prefs(void)
{
    char       *rf_path;
    FILE       *rf;

    rf_path = get_persconffile_path(LANGUAGE_FILE_NAME, FALSE);

    if ((rf = ws_fopen(rf_path, "r")) != NULL) {
        read_prefs_file(rf_path, rf, read_language_pref, NULL);

        fclose(rf);
    }

    g_free(rf_path);
}

gboolean
write_language_prefs(void)
{
    char        *pf_dir_path;
    char        *rf_path;
    FILE        *rf;

    /* To do:
    * - Split output lines longer than MAX_VAL_LEN
    * - Create a function for the preference directory check/creation
    *   so that duplication can be avoided with filter.c
    */

    /* Create the directory that holds personal configuration files, if
        necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        "Can't create directory\n\"%s\"\nfor language file: %s.", pf_dir_path,
        g_strerror(errno));
        g_free(pf_dir_path);
        return FALSE;
    }

    rf_path = get_persconffile_path(LANGUAGE_FILE_NAME, FALSE);
    if ((rf = ws_fopen(rf_path, "w")) == NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        "Can't open recent file\n\"%s\": %s.", rf_path,
        g_strerror(errno));
        g_free(rf_path);
        return FALSE;
    }
    g_free(rf_path);

    fputs("# Language settings file for Wireshark " VERSION ".\n"
        "#\n"
        "# This file is regenerated each time Wireshark is quit.\n"
        "# So be careful, if you want to make manual changes here.\n"
        "\n", rf);

    fprintf(rf, LANGUAGE_PREF_LANGUAGE ": %s\n", language ? language : USE_SYSTEM_LANGUAGE);

    fclose(rf);

    return TRUE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
