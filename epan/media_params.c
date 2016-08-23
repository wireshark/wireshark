/* media_params.c
 * Routines for parsing media type parameters as per RFC 822 and RFC 2045
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

static const char *
ws_get_next_media_type_parameter(const char *pos, gsize *retnamelen,
                                 const char **retvalue, gsize *retvaluelen,
                                 const char **nextp)
{
    const char *p, *namep, *valuep;
    char c;

    p = pos;
    while ((c = *p) != '\0' && g_ascii_isspace(c))
        p++; /* Skip white space */

    if (c == '\0') {
        /* No more parameters left */
        return NULL;
    }

    namep = p;

    /* Look for a '\0' (end of string), '=' (end of parameter name,
       beginning of parameter value), or ';' (end of parameter). */
    while ((c = *p) != '\0' && c != '=' && c != ';')
        p++;
    *retnamelen = (gsize) (p - namep);
    if (c == '\0') {
        /* End of string, so end of parameter, no parameter value */
        if (retvalue != NULL)
            *retvalue = NULL;
        if (retvaluelen != NULL)
            *retvaluelen = 0;
        *nextp = p;
        return namep;
    }
    if (c == ';') {
        /* End of parameter, no parameter value */
        if (retvalue != NULL)
            *retvalue = NULL;
        if (retvaluelen != NULL)
            *retvaluelen = 0;
        *nextp = p + 1;
        return namep;
    }
    /* The parameter has a value.  Skip the '=' */
    p++;
    valuep = p;
    if (retvalue != NULL)
        *retvalue = valuep;
    /* Is the value a quoted string? */
    if (*p == '"') {
        /* Yes. Skip the opening quote, and scan forward looking for
           a non-escaped closing quote. */
        p++;
        for (;;) {
            c = *p;
            if (c == '\0') {
                /* End-of-string.  We're done.
                   (XXX - this is an error.) */
                if (retvaluelen != NULL) {
                    *retvaluelen = (gsize) (p - valuep);
                }
                *nextp = p;
                return namep;
            }
            if (c == '"') {
                /* Closing quote.  Skip it; we're done with
                   the quoted-string. */
                p++;
                break;
            }
            if (c == '\\') {
                /* Backslash; this escapes the next character
                   (quoted-pair). Skip the backslash, and make
                   sure there *is* a next character. */
                p++;
                if (*p == '\0') {
                    /* Nothing left; we're done.
                       (XXX - this is an error.) */
                    break;
                }
            }
            /* Skip the character we just processed. */
            p++;
        }
        /* Now scan forward looking for a '\0' (end of string)
           or ';' (end of parameter), in case there's any
            extra cruft after the quoted-string. */
        while ((c = *p) != '\0' && c != ';')
           p++;
    } else {
        /* No.  Just scan forward looking for a '\0' (end
           of string) or ';' (end of parameter). */
        while ((c = *p) != '\0' && c != ';')
            p++;
    }
    if (c == '\0') {
        /* End of string, so end of parameter */
        if (retvaluelen != NULL) {
            *retvaluelen = (gsize) (p - valuep);
        }
        *nextp = p;
        return namep;
    }
    /* End of parameter; point past the terminating ';' */
    if (retvaluelen != NULL) {
        *retvaluelen = (gsize) (p - valuep);
    }
    *nextp = p + 1;
    return namep;
}

char *
ws_find_media_type_parameter(const char *parameters, const char *key)
{
    const char *p, *name, *value;
    char c;
    gsize keylen, namelen, valuelen;
    char *valuestr, *vp;

    if (parameters == NULL || key == NULL)
        /* we won't be able to find anything */
        return NULL;

    keylen = (gsize) strlen(key);
    if (keylen == 0) {
        /* There's no parameter name to searh for */
        return NULL;
    }
    p = parameters;
    if (*p == '\0') {
        /* There are no parameters in which to search */
        return NULL;
    }

    do {
        /* Get the next parameter. */
        name = ws_get_next_media_type_parameter(p, &namelen, &value,
                                                &valuelen, &p);
        if (name == NULL) {
            /* No more parameters - not found. */
            return NULL;
        }

        /* Is it the parameter we're looking for? */
        if (namelen == keylen && g_ascii_strncasecmp(name, key, keylen) == 0) {
            /* Yes. */
            break;
        }
    } while (*p);

    if (value == NULL) {
        /* The parameter doesn't have a value. */
        return NULL;
    }

    /* We found the parameter with that name; now extract the value. */
    valuestr = (char *)g_malloc(valuelen + 1);
    vp = valuestr;
    p = value;
    /* Is the value a quoted string? */
    if (*p == '"') {
        /* Yes. Skip the opening quote, and scan forward looking for
           a non-escaped closing quote, copying characters. */
        p++;
        for (;;) {
            c = *p;
            if (c == '\0') {
                /* End-of-string.  We're done.
                   (XXX - this is an error.) */
                *vp = '\0';
                return valuestr;
            }
            if (c == '"') {
                /* Closing quote.  Skip it; we're done with
                   the quoted-string. */
                p++;
                break;
            }
            if (c == '\\') {
                /* Backslash; this escapes the next character
                   (quoted-pair). Skip the backslash, and make
                   sure there *is* a next character. */
                p++;
                if (*p == '\0') {
                    /* Nothing left; we're done.
                       (XXX - this is an error.) */
                    break;
                }
            }
            /* Copy the character. */
            *vp++ = *p++;
        }
    } else {
        /* No.  Just scan forward until we see a '\0' (end of
           string or a non-token character, copying characters. */
        while ((c = *p) != '\0' && g_ascii_isgraph(c) && c != '(' &&
                c != ')' && c != '<' && c != '>' && c != '@' &&
                c != ',' && c != ';' && c != ':' && c != '\\' &&
                c != '"' && c != '/' && c != '[' && c != ']' &&
                c != '?' && c != '=' && c != '{' && c != '}') {
            *vp++ = c;
            p++;
        }
    }
    *vp = '\0';
    return valuestr;
}
