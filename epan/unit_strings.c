/* unit_strings.c
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

#include "config.h"

#include <wsutil/str_util.h>
#include "unit_strings.h"

char* unit_name_string_get_value(guint32 value, unit_name_string* units)
{
    if (units->plural == NULL)
        return units->singular;

    return plurality(value, units->singular, units->plural);
}

char* unit_name_string_get_value64(guint64 value, unit_name_string* units)
{
    if (units->plural == NULL)
        return units->singular;

    return plurality(value, units->singular, units->plural);
}

/*
 * A default set of unit strings that dissectors can use for
 * header fields.  Some units intentionally have a space
 * character in them for spacing between unit and value
 */
const unit_name_string units_foot_feet = { " foot", " feet" };
const unit_name_string units_bit_bits = { " bit", " bits" };
const unit_name_string units_byte_bytes = { " byte", " bytes" };
const unit_name_string units_word_words = { " word", " words" };
const unit_name_string units_second_seconds = { " second", " seconds" };
const unit_name_string units_seconds = { "s", NULL };
const unit_name_string units_millisecond_milliseconds = { " millisecond", " milliseconds" };
const unit_name_string units_milliseconds = { "ms", NULL };
const unit_name_string units_nanosecond_nanoseconds = { " nanosecond", " nanoseconds" };
const unit_name_string units_degree_degrees = { " degree", " degrees" };
const unit_name_string units_ghz = { "GHz", NULL };
const unit_name_string units_hz = { "Hz", NULL };
const unit_name_string units_hz_s = { "Hz/s", NULL };


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