/* language.c
 * Language "preference" handling routines
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include <ui/ui_prefs.h>

#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>

#include "ui/language.h"

#define LANGUAGE_FILE_NAME      "language"
#define LANGUAGE_PREF_LANGUAGE  "language"

static char *language = USE_SYSTEM_LANGUAGE;
static module_t* language_module;


char* get_language_used(void)
{
    return language;
}

void set_language_used(const char* lang)
{
    wmem_free(language_module->scope, language);
    language = wmem_strdup(language_module->scope, lang);
}


static pref_t*
language_deprecated_settings(module_t* module, const char* name)
{
        if (strcmp(name, "language") == 0) {
                return prefs_find_preference(module, LANGUAGE_PREF_LANGUAGE);
        }

        return NULL;
}

static void
language_apply_cb(void)
{
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
    if ((language == NULL) || !*language || strcmp(language, "auto") == 0 ||
        strcmp(language, "(null)") == 0) {
        wmem_free(language_module->scope, language);
        language = wmem_strdup(language_module->scope, USE_SYSTEM_LANGUAGE);
    }
}

void language_init(void)
{
    language_module = ui_prefs_register_module("ui_language", "Language options", "Language options", NULL, language_apply_cb, language_deprecated_settings);
    /* Language preferences don't affect dissection */
    prefs_set_module_effect_flags(language_module, PREF_EFFECT_GUI);

    prefs_register_string_preference(language_module, LANGUAGE_PREF_LANGUAGE, "Language",
                                    "The language used for displaying application text", (const char**)&language);

}

void language_cleanup(void)
{
}

void
read_language_prefs(const char* app_env_var_prefix)
{
    char       *rf_path;
    FILE       *rf;

    rf_path = get_persconffile_path(LANGUAGE_FILE_NAME, false, app_env_var_prefix);

    if ((rf = ws_fopen(rf_path, "r")) != NULL) {
        read_prefs_file(rf_path, rf, ui_prefs_read_pref, NULL);

        fclose(rf);
    }

    prefs_apply(language_module);

    g_free(rf_path);
}

bool
write_language_prefs(const char* app_env_var_prefix, char** err_info)
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
    if (create_persconffile_dir(app_env_var_prefix, &pf_dir_path) == -1) {
        *err_info = g_strdup_printf("Can't create directory\n\"%s\"\nfor language file: %s.",
                                    pf_dir_path, g_strerror(errno));
        g_free(pf_dir_path);
        return false;
    }

    rf_path = get_persconffile_path(LANGUAGE_FILE_NAME, false, app_env_var_prefix);
    if ((rf = ws_fopen(rf_path, "w")) == NULL) {
        *err_info = g_strdup_printf("Can't open recent file\n\"%s\": %s.",
                                    rf_path, g_strerror(errno));
        g_free(rf_path);
        return false;
    }
    g_free(rf_path);

    fputs("# Language settings file for Wireshark " VERSION ".\n"
        "#\n"
        "# This file is regenerated each time Wireshark is quit.\n"
        "# So be careful, if you want to make manual changes here.\n"
        "\n", rf);

    ui_prefs_write_pref_arg_t pref_args;
    pref_args.pf = rf;
    ui_prefs_write_module(language_module, &pref_args);

    fclose(rf);

    return true;
}
