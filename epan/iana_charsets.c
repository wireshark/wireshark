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

#define _ICWE_CASE_AND_RETURN(ic_enum_val, ws_enc)    case (ic_enum_val): return (ws_enc);

/*
 * Map a MIBenum code for a charset to a Wireshark string encoding.
 */
unsigned
mibenum_charset_to_encoding (unsigned charset)
{
    switch (charset) {
        /* Expand macro result in:
         *
         *    case IANA_CS_US_ASCII:
         *       return ENC_NA|ENC_ASCII;
         *
         *    case IANA_CS_ISO_8859_1:
         *       return ENC_NA|ENC_ISO_8859_1;
         *    ...
         */
        IANA_CHARSETS_WS_ENCODING_MAP_LIST(_ICWE_CASE_AND_RETURN, ICWE_MAP_TO_ENUM_MAP_ONLY, ICWE_SELECT_N1)

        default:
            return ENC_NA|_DEFAULT_WS_ENC;
    }
}

/* define a value_string array named mibenum_vals_character_sets */
VALUE_STRING_ARRAY(mibenum_vals_character_sets);

value_string_ext mibenum_vals_character_sets_ext = VALUE_STRING_EXT_INIT(mibenum_vals_character_sets);

/* define an iana charset enum_val_t array named mibenum_vals_character_sets_ev_array */
VS_LIST_TO_ENUM_VAL_T_ARRAY_GLOBAL_DEF(mibenum_vals_character_sets, mibenum_vals_character_sets_ev_array);

/* define an Wireshark supported iana charset enum_val_t array */
VS_LIST_TO_ENUM_VAL_T_ARRAY_GLOBAL_DEF(ws_supported_mibenum_vals_character_sets, ws_supported_mibenum_vals_character_sets_ev_array);

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
