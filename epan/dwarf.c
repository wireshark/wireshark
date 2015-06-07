/* dwarf.c
 * Common DWARF parts
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

#include <epan/tvbuff.h>

#include "dwarf.h"

gint
dissect_uleb128(tvbuff_t *tvb, gint offset, guint64 *value)
{
    guint  start_offset = offset;
    guint  shift = 0;
    guint8 byte;

    *value = 0;

    do {
        byte = tvb_get_guint8(tvb, offset);
        offset += 1;

        *value |= ((guint64)(byte & 0x7F) << shift);
        shift += 7;
    } while (byte & 0x80);

    return offset - start_offset;
}

gint
dissect_leb128(tvbuff_t *tvb, gint offset, gint64 *value)
{
    guint  start_offset = offset;
    guint  shift = 0;
    guint8 byte;

    *value = 0;

    do {
        byte = tvb_get_guint8(tvb, offset);
        offset += 1;

        *value |= ((guint64)(byte & 0x7F) << shift);
        shift += 7;
    } while (byte & 0x80);

    if (shift < 64 && byte & 0x40)
        *value |= - ((gint64)1 << shift);

    return offset - start_offset;
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
