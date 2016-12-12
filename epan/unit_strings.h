/* unit_strings.h
 * Units to append to field values
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __UNIT_STRINGS_H__
#define __UNIT_STRINGS_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Units to append to field values
 */

/* For BASE_UNIT_STRING, the display format for adding units */
typedef struct unit_name_string {
    char *singular;     /* name to use for 1 unit */
    char *plural;          /* name to use for < 1 or > 1 units */
} unit_name_string;

WS_DLL_PUBLIC char* unit_name_string_get_value(guint32 value, unit_name_string* units);
WS_DLL_PUBLIC char* unit_name_string_get_value64(guint64 value, unit_name_string* units);

/*
 * A default set of unit strings that dissectors can use for
 * header fields.
 */
WS_DLL_PUBLIC const unit_name_string units_foot_feet;
WS_DLL_PUBLIC const unit_name_string units_bit_bits;
WS_DLL_PUBLIC const unit_name_string units_byte_bytes;
WS_DLL_PUBLIC const unit_name_string units_word_words;
WS_DLL_PUBLIC const unit_name_string units_second_seconds; // full unit name "second[s?]"
WS_DLL_PUBLIC const unit_name_string units_seconds;        //only seconds abbreviation "s"
WS_DLL_PUBLIC const unit_name_string units_millisecond_milliseconds; // full unit name "millisecond[s?]"
WS_DLL_PUBLIC const unit_name_string units_milliseconds;        //only seconds abbreviation "ms"

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UNIT_STRINGS_H__ */

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
