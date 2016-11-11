/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>

#include <ftypes-int.h>
#include <epan/guid-utils.h>
#include <epan/to_str.h>

static void
guid_fvalue_set_guid(fvalue_t *fv, const e_guid_t *value)
{
    fv->value.guid = *value;
}

static gpointer
value_get(fvalue_t *fv)
{
    return &(fv->value.guid);
}

static gboolean
get_guid(const char *s, e_guid_t *guid)
{
    size_t i, n;
    const char *p;
    char digits[9];
    static const char fmt[] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";

    n = strlen(s);
    if (n != strlen(fmt))
        return FALSE;
    for (i=0; i<n; i++) {
        if (fmt[i] == 'X') {
            if (!g_ascii_isxdigit(s[i]))
                return FALSE;
        } else {
            if (s[i] != fmt[i])
                return FALSE;
        }
    }

    p = s;
    g_strlcpy(digits, p, 9);
    guid->data1 = (guint32)strtoul(digits, NULL, 16);
    p += 9;
    g_strlcpy(digits, p, 5);
    guid->data2 = (guint16)strtoul(digits, NULL, 16);
    p += 5;
    g_strlcpy(digits, p, 5);
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
guid_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
     e_guid_t guid;

    if (!get_guid(s, &guid)) {
        if (err_msg != NULL)
            *err_msg = g_strdup_printf("\"%s\" is not a valid GUID.", s);
        return FALSE;
    }

    fv->value.guid = guid;
    return TRUE;
}

static int
guid_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_, int field_display _U_)
{
    return GUID_STR_LEN;
}

static void
guid_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_, char *buf, unsigned int size)
{
    guid_to_str_buf(&fv->value.guid, buf, size);
}

static gboolean
cmp_eq(const fvalue_t *a, const fvalue_t *b)
{
    return memcmp(&a->value.guid, &b->value.guid, sizeof(e_guid_t)) == 0;
}

static gboolean
cmp_ne(const fvalue_t *a, const fvalue_t *b)
{
    return memcmp(&a->value.guid, &b->value.guid, sizeof(e_guid_t)) != 0;
}

void
ftype_register_guid(void)
{

    static ftype_t guid_type = {
        FT_GUID,              /* ftype */
        "FT_GUID",           /* name */
        "Globally Unique Identifier",            /* pretty_name */
        GUID_LEN,            /* wire_size */
        NULL,                /* new_value */
        NULL,                /* free_value */
        guid_from_unparsed,  /* val_from_unparsed */
        NULL,                /* val_from_string */
        guid_to_repr,        /* val_to_string_repr */
        guid_repr_len,       /* len_string_repr */

        NULL,                /* set_value_byte_array */
        NULL,                /* set_value_bytes */
        guid_fvalue_set_guid, /* set_value_guid */
        NULL,                /* set_value_time */
        NULL,                /* set_value_string */
        NULL,                /* set_value_protocol */
        NULL,                /* set_value_uinteger */
        NULL,                /* set_value_sinteger */
        NULL,                /* set_value_uinteger64 */
        NULL,                /* set_value_sinteger64 */
        NULL,                /* set_value_floating */

        value_get,           /* get_value */
        NULL,                /* get_value_uinteger */
        NULL,                /* get_value_sinteger */
        NULL,                /* get_value_uinteger64 */
        NULL,                /* get_value_sinteger64 */
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
