/*
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>

#include <ftypes-int.h>
#include <epan/guid-utils.h>

static void
guid_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
    g_assert(!already_copied);
    fv->value.guid = *(e_guid_t*)value;
}

static gpointer
value_get(fvalue_t *fv)
{
    return &(fv->value.guid);
}

static gboolean
get_guid(char *s, e_guid_t *guid)
{
    size_t i, n;
    char *p, digits[9];
    static const char fmt[] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";

    n = strlen(s);
    if (n != strlen(fmt))
        return FALSE;
    for (i=0; i<n; i++) {
        if (fmt[i] == 'X') {
            if (!isxdigit((guchar)s[i]))
                return FALSE;
        } else {
            if (s[i] != fmt[i])
                return FALSE;
        }
    }
    
    p = s;
    strncpy(digits, p, 8); 
    digits[8] = '\0';
    guid->data1 = strtoul(digits, NULL, 16);
    p += 9;
    strncpy(digits, p, 4); 
    digits[4] = '\0';
    guid->data2 = (guint16)strtoul(digits, NULL, 16);
    p += 5;
    strncpy(digits, p, 4); 
    digits[4] = '\0';
    guid->data3 = (guint16)strtoul(digits, NULL, 16);
    p += 5;
    for (i=0; i < sizeof(guid->data4); i++) {
        if (*p == '-') p++;
        digits[0] = *(p++);
        digits[1] = *(p++);
        digits[2] = '\0';
        guid->data4[i] = (guint8)strtoul(digits, NULL, 16);
    }
    return TRUE;
}

static gboolean
guid_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
     e_guid_t guid;

    if (!get_guid(s, &guid)) {
        logfunc("\"%s\" is not a valid GUID.", s);
        return FALSE;
    }

    fv->value.guid = guid;
    return TRUE;
}

static int
guid_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
    return GUID_STR_LEN;
}

static void
guid_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
    guid_to_str_buf(&fv->value.guid, buf, GUID_STR_LEN);
}

static gboolean
cmp_eq(fvalue_t *a, fvalue_t *b)
{
    return memcmp(&a->value.guid, &b->value.guid, sizeof(e_guid_t)) == 0;
}

static gboolean
cmp_ne(fvalue_t *a, fvalue_t *b)
{
    return memcmp(&a->value.guid, &b->value.guid, sizeof(e_guid_t)) != 0;
}

void
ftype_register_guid(void)
{

    static ftype_t guid_type = {
        FT_GUID,              /* ftype */
        "GUID",              /* name */
        "Globally Unique Identifier",            /* pretty_name */
        GUID_LEN,            /* wire_size */
        NULL,                /* new_value */
        NULL,                /* free_value */
        guid_from_unparsed,  /* val_from_unparsed */
        NULL,                /* val_from_string */
        guid_to_repr,        /* val_to_string_repr */
        guid_repr_len,       /* len_string_repr */

        guid_fvalue_set,     /* set_value */
        NULL,                /* set_value_uinteger */
        NULL,                /* set_value_sinteger */
        NULL,                /* set_value_integer64 */
        NULL,                /* set_value_floating */

        value_get,           /* get_value */
        NULL,                /* get_value_uinteger */
        NULL,                /* get_value_sinteger */
        NULL,                /* get_value_integer64 */
        NULL,                /* get_value_floating */

        cmp_eq,
        cmp_ne,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,                /* cmp_matches */

        NULL,
        NULL,
    };

    ftype_register(FT_GUID, &guid_type);
}
