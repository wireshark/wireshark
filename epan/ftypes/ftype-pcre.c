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

/* Perl-Compatible Regular Expression (PCRE) internal field type.
 * Used with the "matches" dfilter operator, allowing efficient
 * compilation and studying of a PCRE pattern in dfilters.
 */

#include "config.h"

#include <ftypes-int.h>

#include <glib.h>
#include <string.h>

static void
gregex_fvalue_new(fvalue_t *fv)
{
    fv->value.re = NULL;
}

static void
gregex_fvalue_free(fvalue_t *fv)
{
    if (fv->value.re) {
        g_regex_unref(fv->value.re);
        fv->value.re = NULL;
    }
}

/* Determines whether pattern needs to match raw byte sequences */
static gboolean
raw_flag_needed(const gchar *pattern)
{
    gboolean found = FALSE;
    const gchar *s = pattern;
    size_t i, len;

    /* find any character whose hex value is two letters */
    len = strlen(s);
    for (i = 0; i < len; i++) {
        /* Upper and lower-nibble must be >= 0xA */
        if ((guchar)(s[i] & 0xF0) >= 0xA0 &&
            (guchar)(s[i] & 0x0F) >= 0x0A)
        {
            found = TRUE;
            break;
        }
    }
    return found;
}

/* Generate a FT_PCRE from a parsed string pattern.
 * On failure, if err_msg is non-null, set *err_msg to point to a
 * g_malloc()ed error message. */
static gboolean
val_from_string(fvalue_t *fv, const char *pattern, gchar **err_msg)
{
    GError *regex_error = NULL;
    GRegexCompileFlags cflags = G_REGEX_OPTIMIZE;

    /* Set RAW flag only if pattern requires matching raw byte
       sequences. Otherwise, omit it so that GRegex treats its
       input as UTF8-encoded string. */
    if (raw_flag_needed(pattern)) {
        cflags = (GRegexCompileFlags)(G_REGEX_OPTIMIZE | G_REGEX_RAW);
    }

    /* Free up the old value, if we have one */
    gregex_fvalue_free(fv);

    fv->value.re = g_regex_new(
            pattern,            /* pattern */
            cflags,             /* Compile options */
            (GRegexMatchFlags)0,                  /* Match options */
            &regex_error        /* Compile / study errors */
            );

    if (regex_error) {
        if (err_msg) {
            *err_msg = g_strdup(regex_error->message);
        }
        g_error_free(regex_error);
        if (fv->value.re) {
            g_regex_unref(fv->value.re);
        }
        return FALSE;
    }
    return TRUE;
}

/* Generate a FT_PCRE from an unparsed string pattern.
 * On failure, if err_msg is non-null, set *err_msg to point to a
 * g_malloc()ed error message. */
static gboolean
val_from_unparsed(fvalue_t *fv, const char *pattern, gboolean allow_partial_value, gchar **err_msg)
{
    g_assert(! allow_partial_value);

    return val_from_string(fv, pattern, err_msg);
}

static int
gregex_repr_len(fvalue_t *fv, ftrepr_t rtype, int field_display _U_)
{
    g_assert(rtype == FTREPR_DFILTER);
    return (int)strlen(g_regex_get_pattern(fv->value.re));
}

static void
gregex_to_repr(fvalue_t *fv, ftrepr_t rtype, int field_display _U_, char *buf, unsigned int size)
{
    g_assert(rtype == FTREPR_DFILTER);
    g_strlcpy(buf, g_regex_get_pattern(fv->value.re), size);
}

/* BEHOLD - value contains the string representation of the regular expression,
 * and we want to store the compiled PCRE RE object into the value. */
static void
gregex_fvalue_set(fvalue_t *fv, const char *value)
{
    g_assert(value != NULL);
    /* Free up the old value, if we have one */
    gregex_fvalue_free(fv);
    val_from_unparsed(fv, value, FALSE, NULL);
}

static gpointer
gregex_fvalue_get(fvalue_t *fv)
{
    return fv->value.re;
}

void
ftype_register_pcre(void)
{
    static ftype_t pcre_type = {
        FT_PCRE,            /* ftype */
        "FT_PCRE",          /* name */
        "Compiled Perl-Compatible Regular Expression (GRegex) object", /* pretty_name */
        0,                  /* wire_size */
        gregex_fvalue_new,  /* new_value */
        gregex_fvalue_free, /* free_value */
        val_from_unparsed,  /* val_from_unparsed */
        val_from_string,    /* val_from_string */
        gregex_to_repr,     /* val_to_string_repr */
        gregex_repr_len,    /* len_string_repr */

        NULL,               /* set_value_byte_array */
        NULL,               /* set_value_bytes */
        NULL,               /* set_value_guid */
        NULL,               /* set_value_time */
        gregex_fvalue_set,  /* set_value_string */
        NULL,               /* set_value_protocol */
        NULL,               /* set_value_uinteger */
        NULL,               /* set_value_sinteger */
        NULL,               /* set_value_uinteger64 */
        NULL,               /* set_value_sinteger64 */
        NULL,               /* set_value_floating */

        gregex_fvalue_get,  /* get_value */
        NULL,               /* get_value_uinteger */
        NULL,               /* get_value_sinteger */
        NULL,               /* get_value_uinteger64 */
        NULL,               /* get_value_sinteger64 */
        NULL,               /* get_value_floating */

        NULL,               /* cmp_eq */
        NULL,               /* cmp_ne */
        NULL,               /* cmp_gt */
        NULL,               /* cmp_ge */
        NULL,               /* cmp_lt */
        NULL,               /* cmp_le */
        NULL,               /* cmp_bitwise_and */
        NULL,               /* cmp_contains */
        NULL,               /* cmp_matches */

        NULL,               /* len */
        NULL,               /* slice */
    };
    ftype_register(FT_PCRE, &pcre_type);
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
