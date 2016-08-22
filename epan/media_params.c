/* media_params.c
 * Routines for parsing media type parameters
 * Copyright 2004, Anders Broman.
 * Copyright 2004, Olivier Biot.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
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

#include <glib.h>

#include <epan/media_params.h>

/* Return the index of a given char in the given string,
 * or -1 if not found.
 */
gint
index_of_char(const char *str, const char c)
{
    gint len = 0;
    const char *p = str;

    while (*p && *p != c) {
        p++;
        len++;
    }

    if (*p)
        return len;
    return -1;
}

char *
ws_find_media_type_parameter(const char *parameters, const char *key, int *retlen)
{
    const char *start, *p;
    int   keylen = 0;
    int   len = 0;

    if(!parameters || !*parameters || !key || strlen(key) == 0)
        /* we won't be able to find anything */
        return NULL;

    keylen = (int) strlen(key);
    p = parameters;

    while (*p) {

        while ((*p) && g_ascii_isspace(*p))
            p++; /* Skip white space */

        if (g_ascii_strncasecmp(p, key, keylen) == 0)
            break;
        /* Skip to next parameter */
        p = strchr(p, ';');
        if (p == NULL)
        {
            return NULL;
        }
        p++; /* Skip semicolon */

    }
    if (*p == 0x0)
        return NULL;  /* key wasn't found */

    start = p + keylen;
    if (start[0] == 0) {
        return NULL;
    }

    /*
     * Process the parameter value
     */
    if (start[0] == '"') {
        /*
         * Parameter value is a quoted-string
         */
        start++; /* Skip the quote */
        len = index_of_char(start, '"');
        if (len < 0) {
            /*
             * No closing quote
             */
            return NULL;
        }
    } else {
        /*
         * Look for end of boundary
         */
        p = start;
        while (*p) {
            if (*p == ';' || g_ascii_isspace(*p))
                break;
            p++;
            len++;
        }
    }

    if(retlen)
        (*retlen) = len;

    /*
     * This is one of those ugly routines like strchr() where you can
     * pass in a constant or non-constant string, and the result
     * points into that string and inherits the constness of the
     * input argument, but C doesn't support that, so the input
     * parameter is const char * and the result is char *.
     */
    return (char *)start;
}
