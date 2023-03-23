/* iana_charsets.c
 *
 * Routines and tables for IANA-registered character sets
 *
 *    http://www.iana.org/assignments/character-sets/character-sets.xhtml
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/proto.h>
#include <epan/value_string.h>
#include <epan/params.h>

#include <epan/iana_charsets.h>

/*
 * Map a MIBenum code for a charset to a Wireshark string encoding.
 */
guint
mibenum_charset_to_encoding (guint charset)
{
    switch (charset) {
        case IANA_CS_US_ASCII:
            return ENC_NA|ENC_ASCII;

        case IANA_CS_ISO_8859_1:
            return ENC_NA|ENC_ISO_8859_1;

        case IANA_CS_ISO_8859_2:
            return ENC_NA|ENC_ISO_8859_2;

        case IANA_CS_ISO_8859_3:
            return ENC_NA|ENC_ISO_8859_3;

        case IANA_CS_ISO_8859_4:
            return ENC_NA|ENC_ISO_8859_4;

        case IANA_CS_ISO_8859_5:
            return ENC_NA|ENC_ISO_8859_5;

        case IANA_CS_ISO_8859_6:
            return ENC_NA|ENC_ISO_8859_6;

        case IANA_CS_ISO_8859_7:
            return ENC_NA|ENC_ISO_8859_7;

        case IANA_CS_ISO_8859_8:
            return ENC_NA|ENC_ISO_8859_8;

        case IANA_CS_ISO_8859_9:
            return ENC_NA|ENC_ISO_8859_9;

        case IANA_CS_ISO_8859_10:
            return ENC_NA|ENC_ISO_8859_10;

        case IANA_CS_UTF_8:
            return ENC_NA|ENC_UTF_8;

        case IANA_CS_ISO_8859_13:
            return ENC_NA|ENC_ISO_8859_13;

        case IANA_CS_ISO_8859_14:
            return ENC_NA|ENC_ISO_8859_14;

        case IANA_CS_ISO_8859_15:
            return ENC_NA|ENC_ISO_8859_15;

        case IANA_CS_ISO_8859_16:
            return ENC_NA|ENC_ISO_8859_16;

        case IANA_CS_GBK:
        case IANA_CS_GB18030:
        case IANA_CS_GB2312:
            /* GB18030 is compatible with GBK and GB2312 */
            return ENC_NA|ENC_GB18030;

        case IANA_CS_ISO_10646_UCS_2:
            /*
             * The IANA page says:
             *
             *    this needs to specify network byte order: the
             *    standard does not specify
             *
             * so presumably this means "big-endian UCS-2".
             */
            return ENC_BIG_ENDIAN|ENC_UCS_2;

        case IANA_CS_ISO_10646_UCS_4:
            /*
             * The IANA page says the same thing as for UCS-2.
             */
            return ENC_BIG_ENDIAN|ENC_UCS_4;

        case IANA_CS_UTF_16BE:
            return ENC_BIG_ENDIAN|ENC_UTF_16;

        case IANA_CS_UTF_16LE:
            return ENC_LITTLE_ENDIAN|ENC_UTF_16;

        case IANA_CS_UTF_16:
            /* XXX - UTF-16 with a BOM at the beginning */
            return ENC_LITTLE_ENDIAN|ENC_UTF_16;

        case IANA_CS_IBM437:
            return ENC_NA|ENC_CP437;

        case IANA_CS_TIS_620:
            return ENC_NA|ENC_ISO_8859_11;

        default:
            return ENC_NA|ENC_ASCII;
    }
}

/* define a value_string array named mibenum_vals_character_sets */
VALUE_STRING_ARRAY(mibenum_vals_character_sets);

value_string_ext mibenum_vals_character_sets_ext = VALUE_STRING_EXT_INIT(mibenum_vals_character_sets);

/* define an iana charset enum_val_t array named mibenum_vals_character_sets_ev_array */
VS_LIST_TO_ENUM_VAL_T_ARRAY_GLOBAL_DEF(mibenum_vals_character_sets, mibenum_vals_character_sets_ev_array);

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
