/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
    char digits[3];
    static const char fmt[] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";
    const size_t fmtchars = sizeof(fmt) - 1;

    n = strnlen(s, fmtchars);
    if (n != fmtchars)
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
    guid->data1 = (guint32)strtoul(p, NULL, 16);
    p += 9;
    guid->data2 = (guint16)strtoul(p, NULL, 16);
    p += 5;
    guid->data3 = (guint16)strtoul(p, NULL, 16);
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

        { .set_value_guid = guid_fvalue_set_guid }, /* union set_value */
        { .get_value_ptr = value_get },             /* union get_value */

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
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
