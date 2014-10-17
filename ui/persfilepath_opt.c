/* persfilepath_opt.c
 * Routines to handle command-line options to set paths for directories
 * containing personal files (configuration, saved captures)
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

#include "ui/persfilepath_opt.h"

/*
 * process command line option that affects the paths of the directories
 * used for personal files (configuration, saved captures)
 */
gboolean
persfilepath_opt(int opt _U_, const char *optstr)
{
    gchar *p, *colonp;

    colonp = strchr(optstr, ':');
    if (colonp == NULL) {
        return FALSE;
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
        return FALSE;
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
        return FALSE;
    }

    if (strcmp(optstr,"persconf") == 0) {
        set_persconffile_dir(p);
    } else if (strcmp(optstr,"persdata") == 0) {
        set_persdatafile_dir(p);
    } else {
        /* XXX - might need to add the temp file path */
        return FALSE;
    }
    *colonp = ':'; /* put the colon back */
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
