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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
    guint value   = 0, previous_value;
    guint octet;
    guint counter = 0;

#ifdef DEBUG
    fprintf (stderr,
            "dissect_wap: Starting tvb_get_guintvar at offset %d\n", offset);
#endif

    do {
        octet = tvb_get_guint8 (tvb, offset+counter);

        counter++;

        previous_value = value;
        value <<= 7;  /* Value only exists in 7 of the 8 bits */
        value += (octet & 0x7F);
        if (value < previous_value) {
            /* overflow; clamp the value at UINT_MAX */
            proto_tree_add_expert(NULL, pinfo, ei, tvb, offset, counter);
            value = UINT_MAX;
        }

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
