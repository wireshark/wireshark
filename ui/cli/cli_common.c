/* cli_common.c
 * Common routines for command-line applications
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <stdio.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/wmem/wmem_strutl.h>
#include <wsutil/cmdarg_err.h>
#include <ui/profile.h>

#include "cli_common.h"

static void
profiles_dump_dir(FILE* output, const char* profile_dir, const char* str_type)
{
    GList* profiles = profile_get_names(profile_dir);

    for (GList* iter = profiles; iter; iter = g_list_next(iter)) {
        fprintf(output, "%s\t%s\n", (const char*)iter->data, str_type);
    }
    g_list_free_full(profiles, g_free);
}

bool
profiles_dump(const char* app_env_var_prefix, const char* filter)
{
    char* profiles_dir;

    if ((filter == NULL) || (strcmp(filter, "all") == 0)) {

        /* Add default profile */
        fprintf(stdout, "%s\tdefault\n", DEFAULT_PROFILE);

        /* Personal profiles */
        profiles_dir = get_profiles_dir(app_env_var_prefix);
        profiles_dump_dir(stdout, profiles_dir, "personal");
        g_free(profiles_dir);

        /* Global profiles */
        profiles_dir = get_global_profiles_dir(app_env_var_prefix);
        profiles_dump_dir(stdout, profiles_dir, "global");
        g_free(profiles_dir);
    }
    else if (strcmp(filter, "global") == 0) {

        profiles_dir = get_global_profiles_dir(app_env_var_prefix);
        profiles_dump_dir(stdout, profiles_dir, filter);
        g_free(profiles_dir);
    }
    else if (strcmp(filter, "personal") == 0) {

        profiles_dir = get_profiles_dir(app_env_var_prefix);
        profiles_dump_dir(stdout, profiles_dir, filter);
        g_free(profiles_dir);

    }
    else {
        cmdarg_err("Invalid profile filter \"%s\". Valid filters are \"global\", \"personal\", and \"all\".", filter);
        return false;
    }

    return true;
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
 *
 */
