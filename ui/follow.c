/* follow.c
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

#include <wsutil/filesystem.h>
#include <epan/dfilter/dfilter.h>

#include "ui/follow.h"

#ifdef HAVE_LIBZ
static char *
sgetline(char *str, int *next)
{
    char *end;

    end = strstr(str, "\r\n");
    if (!end) {
        *next = (int)strlen(str);
        return NULL;
    }
    *end = '\0';
    *next = (int)(end-str+2);
    return str;
}

gboolean
parse_http_header(char *data, size_t len, size_t *content_start)
{
    char *tmp, *copy, *line;
    size_t pos = 0;
    int next_line;
    gboolean is_gzipped;

    /* XXX handle case where only partial header is passed in here.
     * we should pass something back to indicate whether header is complete.
     * (if not, is_gzipped is may still be unknown)
     */

    /*
     * In order to parse header, we duplicate data and tokenize lines.
     * We aren't interested in actual data, so use g_strndup instead of memcpy
     * to (possibly) copy fewer bytes (e.g., if a nul byte exists in data)
     * This also ensures that we have a terminated string for further
     * processing.
     */
    tmp = copy = g_strndup(data, len);
    if (!tmp) {
        *content_start = 0;
        return FALSE;
    }

    /* skip HTTP... line*/
    /*line = */sgetline(tmp, &next_line);

    tmp += next_line;
    pos += next_line;

    is_gzipped = FALSE;

    *content_start = -1;
    while ((line = sgetline(tmp, &next_line))) {
        char *key, *val, *c;

        tmp += next_line;
        pos += next_line;

        if (strlen(line) == 0) {
            /* end of header*/
            break;
        }

        c = strchr(line, ':');
        if (!c) break;

        key = line;
        *c = '\0';
        val = c+2;

        if (!strcmp(key, "Content-Encoding") && strstr(val, "gzip")) {
            is_gzipped = TRUE;
        }
    }
    *content_start = pos;
    g_free(copy);
    return is_gzipped;
}
#endif


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
