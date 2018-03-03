/* packet-wap.c
 *
 * Utility routines for WAP dissectors
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
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

#include <stdio.h>

#include <epan/packet.h>
#include "packet-wap.h"

/*
 * Accessor to retrieve variable length int as used in WAP protocol.
 * The value is encoded in the lower 7 bits. If the top bit is set, then the
 * value continues into the next byte.
 * The octetCount parameter holds the number of bytes read in order to return
 * the final value. Can be pre-initialised to start at offset+count.
*/
guint
tvb_get_guintvar (tvbuff_t *tvb, guint offset,
        guint *octetCount, packet_info *pinfo, expert_field *ei)
{
    guint value   = 0;
    guint octet;
    guint counter = 0;

#ifdef DEBUG
    fprintf (stderr,
            "dissect_wap: Starting tvb_get_guintvar at offset %d\n", offset);
#endif

    do {
        octet = tvb_get_guint8 (tvb, offset+counter);

        counter++;
        if (counter > sizeof(value)) {
            proto_tree_add_expert(NULL, pinfo, ei, tvb, offset, counter);
            value = 0;
            counter = 0;
            break;
        }

        value <<= 7;  /* Value only exists in 7 of the 8 bits */
        value += (octet & 0x7F);

#ifdef DEBUG
        fprintf(stderr,
            "dissect_wap: computing: octet is %d (0x%02x), count=%d, value=%d\n",
                 octet, octet, counter, value);
#endif
    } while (octet & 0x80);

#ifdef DEBUG
    fprintf (stderr,
            "dissect_wap: Leaving tvb_get_guintvar count=%d, value=%u\n",
            counter, value);
#endif

    if (octetCount)
        *octetCount = counter;

    return value;
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
