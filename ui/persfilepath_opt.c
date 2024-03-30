/* persfilepath_opt.c
 * Routines to handle command-line options to set paths for directories
 * containing personal files (configuration, saved captures)
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

#include <wsutil/filesystem.h>

#include "ui/persfilepath_opt.h"

/*
 * process command line option that affects the paths of the directories
 * used for personal files (configuration, saved captures)
 */
bool
persfilepath_opt(int opt _U_, const char *optstr)
{
    char *p, *colonp;

    colonp = strchr(optstr, ':');
    if (colonp == NULL) {
        return false;
    }

    p = colonp;
    *p++ = '\0';

    /*
    * Skip over any white space (there probably won't be any, but
    * as we allow it in the preferences file, we might as well
    * allow it here).
    */
    while (g_ascii_isspace(*p))
        p++;
    if (*p == '\0') {
        /*
         * Put the colon back, so if our caller uses, in an
         * error message, the string they passed us, the message
         * looks correct.
         */
        *colonp = ':';
        return false;
    }

    /* directory should be existing */
    /* XXX - is this a requirement? */
    if(test_for_directory(p) != EISDIR) {
        /*
         * Put the colon back, so if our caller uses, in an
         * error message, the string they passed us, the message
         * looks correct.
         */
        *colonp = ':';
        return false;
    }

    if (strcmp(optstr,"persconf") == 0) {
        set_persconffile_dir(p);
    } else if (strcmp(optstr,"persdata") == 0) {
        set_persdatafile_dir(p);
    } else {
        /* XXX - might need to add the temp file path */
        return false;
    }
    *colonp = ':'; /* put the colon back */
    return true;
}
